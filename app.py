import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation

import bcrypt
import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=hmac.new(
        SUPABASE_SECRET_KEY.encode("utf-8"),
        b"power-admin-panel/flask-session/v1",
        hashlib.sha256,
    ).hexdigest(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024,
)
logging.basicConfig(level=logging.INFO)

SERVICE_STATUSES = {
    "pending": "Хүлээгдэж байна",
    "in_progress": "Хийгдэж байна",
    "completed": "Дууссан",
    "cancelled": "Цуцалсан",
}

SERVICE_TYPES = {
    "shake-diagnostics": {
        "table": "shake_diagnostics",
        "title": "Сэгсэрдэг оношилгоо",
        "description": "Сэгсэрдэг төхөөрөмжөөр хийсэн оношилгооны бүртгэл.",
        "active_section": "diagnostics",
        "select": "id,customer_name,phone,vehicle,plate_number,service_date,details,status,created_at",
        "search_columns": (
            "customer_name",
            "phone",
            "vehicle",
            "plate_number",
            "details",
        ),
        "has_cost": False,
    },
    "aggregate-repairs": {
        "table": "aggregate_repairs",
        "title": "Агрегат засвар",
        "description": "Агрегатын засвар, үнийн бүртгэл.",
        "active_section": "aggregate_repairs",
        "select": "id,customer_name,phone,vehicle,plate_number,service_date,details,cost,status,created_at",
        "search_columns": (
            "customer_name",
            "phone",
            "vehicle",
            "plate_number",
            "details",
        ),
        "has_cost": True,
    },
}


class SupabaseApiError(Exception):
    pass


def supabase_get(table, params):
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise SupabaseApiError(
            "SUPABASE_URL эсвэл SUPABASE_SECRET_KEY тохируулаагүй байна."
        )

    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers={
                "apikey": SUPABASE_SECRET_KEY,
                "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
            },
            params=params,
            timeout=(5, 15),
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise SupabaseApiError("Supabase-тэй холбогдож чадсангүй.") from exc
    except ValueError as exc:
        raise SupabaseApiError("Supabase-ээс буруу хариу ирлээ.") from exc

    if not isinstance(data, list):
        raise SupabaseApiError("Supabase-ээс хүлээгдээгүй хариу ирлээ.")
    return data


def supabase_write(method, table, params, payload=None):
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise SupabaseApiError(
            "SUPABASE_URL эсвэл SUPABASE_SECRET_KEY тохируулаагүй байна."
        )

    try:
        response = requests.request(
            method,
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers={
                "apikey": SUPABASE_SECRET_KEY,
                "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
            params=params,
            json=payload,
            timeout=(5, 15),
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise SupabaseApiError("Supabase дээрх мэдээллийг өөрчилж чадсангүй.") from exc
    except ValueError as exc:
        raise SupabaseApiError("Supabase-ээс буруу хариу ирлээ.") from exc

    if not isinstance(data, list):
        raise SupabaseApiError("Supabase-ээс хүлээгдээгүй хариу ирлээ.")
    return data


def service_type_or_404(service_key):
    service = SERVICE_TYPES.get(service_key)
    if service is None:
        abort(404)
    return service


def get_service_record(service, record_id):
    rows = supabase_get(
        service["table"],
        {
            "select": service["select"],
            "id": f"eq.{record_id}",
            "limit": "1",
        },
    )
    return rows[0] if rows else None


def validate_service_form(service):
    payload = {}
    errors = []
    required_fields = {
        "customer_name": "Харилцагчийн нэр",
        "phone": "Утасны дугаар",
        "vehicle": "Автомашины марк, загвар",
        "plate_number": "Улсын дугаар",
        "details": "Үйлчилгээний тайлбар",
    }

    for field, label in required_fields.items():
        value = request.form.get(field, "").strip()
        max_length = 2000 if field == "details" else 120
        if not value:
            errors.append(f"{label} оруулна уу.")
        elif len(value) > max_length:
            errors.append(f"{label} {max_length} тэмдэгтээс хэтрэхгүй байна.")
        payload[field] = value

    raw_date = request.form.get("service_date", "").strip()
    try:
        payload["service_date"] = datetime.strptime(raw_date, "%Y-%m-%d").date().isoformat()
    except ValueError:
        errors.append("Үйлчилгээний огноог зөв оруулна уу.")

    status = request.form.get("status", "")
    if status not in SERVICE_STATUSES:
        errors.append("Төлөвийн сонголт буруу байна.")
    else:
        payload["status"] = status

    if service["has_cost"]:
        raw_cost = request.form.get("cost", "").strip()
        try:
            cost = Decimal(raw_cost)
            if not cost.is_finite() or cost < 0 or cost > Decimal("9999999999.99"):
                raise InvalidOperation
            payload["cost"] = str(cost.quantize(Decimal("0.01")))
        except (InvalidOperation, ValueError):
            errors.append("Үнийн дүнг 0-ээс багагүй, зөв тоогоор оруулна уу.")

    return payload, errors


def supabase_update_draft_status(draft_id, status):
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise SupabaseApiError(
            "SUPABASE_URL эсвэл SUPABASE_SECRET_KEY тохируулаагүй байна."
        )

    try:
        response = requests.patch(
            f"{SUPABASE_URL}/rest/v1/content_drafts",
            headers={
                "apikey": SUPABASE_SECRET_KEY,
                "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
            params={"id": f"eq.{draft_id}", "status": "eq.draft"},
            json={"status": status},
            timeout=(5, 15),
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise SupabaseApiError("Supabase дээр нооргийн төлөвийг өөрчилж чадсангүй.") from exc
    except ValueError as exc:
        raise SupabaseApiError("Supabase-ээс буруу хариу ирлээ.") from exc

    if not isinstance(data, list):
        raise SupabaseApiError("Supabase-ээс хүлээгдээгүй хариу ирлээ.")
    return bool(data)


def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def valid_csrf_token():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(expected) and hmac.compare_digest(submitted, expected)


@app.get("/brand-logo.svg")
def brand_logo():
    return send_file(
        os.path.join(app.root_path, "Power_Auto_Service_original_colors.svg"),
        mimetype="image/svg+xml",
        max_age=3600,
    )


def render_login(error=None, status=200):
    return render_template("login.html", error=error, csrf_token=csrf_token()), status


@app.get("/")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("login"))

    try:
        drafts = supabase_get(
            "content_drafts",
            {
                "select": "id,title,content,created_at",
                "status": "eq.draft",
                "order": "created_at.desc",
            },
        )
    except SupabaseApiError:
        app.logger.exception("Draft list request failed")
        return render_template(
            "dashboard.html",
            drafts=[],
            email=session["user_email"],
            error="Нооргуудыг ачаалж чадсангүй. Supabase тохиргоо, хүснэгтээ шалгана уу.",
            csrf_token=csrf_token(),
            active_section="content",
        ), 503

    return render_template(
        "dashboard.html",
        drafts=drafts,
        email=session["user_email"],
        error=None,
        csrf_token=csrf_token(),
        active_section="content",
    )


@app.post("/drafts/<int:draft_id>/decision")
def decide_draft(draft_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    if not valid_csrf_token():
        return "Хүсэлтийн баталгаажуулалт амжилтгүй.", 400

    decision = request.form.get("decision", "")
    status_by_decision = {"approve": "published", "reject": "rejected"}
    status = status_by_decision.get(decision)
    if status is None:
        return "Хүсэлт буруу байна.", 400

    try:
        updated = supabase_update_draft_status(draft_id, status)
    except SupabaseApiError:
        app.logger.exception("Draft decision failed for draft id %s", draft_id)
        flash(
            "Нооргийг шинэчилж чадсангүй. Хэрэв татгалзсан бол "
            "Supabase-д supabase_migration.sql-ийг ажиллуулсан эсэхээ шалгана уу.",
            "error",
        )
    else:
        if updated:
            message = (
                "Нийтлэл батлагдаж, төлөв шинэчлэгдлээ."
                if decision == "approve"
                else "Нийтлэлээс татгалзлаа."
            )
            flash(message, "success")
        else:
            flash("Ноорог олдсонгүй эсвэл өмнө нь шийдвэрлэгдсэн байна.", "error")

    return redirect(url_for("dashboard"))


@app.get("/facebook")
def facebook():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template(
        "coming_soon.html",
        email=session["user_email"],
        csrf_token=csrf_token(),
        active_section="facebook",
        section_title="Facebook",
    )


@app.get("/chat")
def chat():
    if "user_email" not in session:
        return redirect(url_for("login"))
    return render_template(
        "coming_soon.html",
        email=session["user_email"],
        csrf_token=csrf_token(),
        active_section="chat",
        section_title="Чат",
    )


@app.get("/bookings")
def bookings():
    if "user_email" not in session:
        return redirect(url_for("login"))

    try:
        rows = supabase_get(
            "bookings",
            {
                "select": "id,customer_name,customer_email,booking_date,booking_time,guest_count,status",
                "order": "booking_date.asc,booking_time.asc",
            },
        )
    except SupabaseApiError:
        app.logger.exception("Booking list request failed")
        return render_template(
            "bookings.html",
            bookings=[],
            email=session["user_email"],
            error="Захиалгуудыг ачаалж чадсангүй. Supabase тохиргоо, хүснэгтээ шалгана уу.",
            csrf_token=csrf_token(),
            active_section="bookings",
        ), 503

    return render_template(
        "bookings.html",
        bookings=rows,
        email=session["user_email"],
        error=None,
        csrf_token=csrf_token(),
        active_section="bookings",
    )


@app.get("/services/<service_key>")
def service_list(service_key):
    if "user_email" not in session:
        return redirect(url_for("login"))
    service = service_type_or_404(service_key)
    query = request.args.get("q", "").strip()[:80]
    search = re.sub(r"[^\w\s.@+-]", " ", query, flags=re.UNICODE).strip()
    params = {
        "select": service["select"],
        "order": "service_date.desc,created_at.desc",
        "limit": "1000",
    }
    if search:
        params["or"] = "(" + ",".join(
            f"{column}.ilike.*{search}*" for column in service["search_columns"]
        ) + ")"

    try:
        records = supabase_get(service["table"], params)
    except SupabaseApiError:
        app.logger.exception("Service record list request failed for %s", service_key)
        return render_template(
            "service_list.html",
            service=service,
            records=[],
            search=query,
            email=session["user_email"],
            error="Бүртгэлүүдийг ачаалж чадсангүй. Эхлээд service_tables.sql файлыг Supabase SQL Editor дээр ажиллуулна уу.",
            csrf_token=csrf_token(),
            active_section=service["active_section"],
            status_labels=SERVICE_STATUSES,
        ), 503

    return render_template(
        "service_list.html",
        service=service,
        records=records,
        search=query,
        email=session["user_email"],
        error=None,
        csrf_token=csrf_token(),
        active_section=service["active_section"],
        status_labels=SERVICE_STATUSES,
    )


@app.route("/services/<service_key>/new", methods=["GET", "POST"])
def service_create(service_key):
    if "user_email" not in session:
        return redirect(url_for("login"))
    service = service_type_or_404(service_key)
    form_data = {
        "service_date": date.today().isoformat(),
        "status": "pending",
        "cost": "0.00",
    }
    errors = []
    status_code = 200

    if request.method == "POST":
        if not valid_csrf_token():
            return "Хүсэлтийн баталгаажуулалт амжилтгүй.", 400
        form_data.update(request.form.to_dict())
        payload, errors = validate_service_form(service)
        if not errors:
            try:
                created = supabase_write("POST", service["table"], {}, payload)
            except SupabaseApiError:
                app.logger.exception("Service record create failed for %s", service_key)
                errors = [
                    "Бүртгэл нэмэгдсэнгүй. SQL Editor дээр service_tables.sql-ийг ажиллуулж, хүснэгтийн багануудыг шалгана уу."
                ]
                status_code = 503
            else:
                if created:
                    flash("Бүртгэл амжилттай нэмэгдлээ.", "success")
                    return redirect(url_for("service_list", service_key=service_key))
                errors = ["Бүртгэл Supabase-д нэмэгдсэнгүй."]
                status_code = 502

    return render_template(
        "service_form.html",
        service=service,
        record=None,
        form_data=form_data,
        errors=errors,
        email=session["user_email"],
        csrf_token=csrf_token(),
        active_section=service["active_section"],
        status_labels=SERVICE_STATUSES,
    ), status_code


@app.route("/services/<service_key>/<int:record_id>/edit", methods=["GET", "POST"])
def service_edit(service_key, record_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    service = service_type_or_404(service_key)
    try:
        record = get_service_record(service, record_id)
    except SupabaseApiError:
        app.logger.exception("Service record lookup failed for %s", service_key)
        abort(503, description="Supabase бүртгэлийг ачаалж чадсангүй.")
    if record is None:
        abort(404)

    form_data = dict(record)
    errors = []
    status_code = 200
    if request.method == "POST":
        if not valid_csrf_token():
            return "Хүсэлтийн баталгаажуулалт амжилтгүй.", 400
        form_data.update(request.form.to_dict())
        payload, errors = validate_service_form(service)
        if not errors:
            try:
                updated = supabase_write(
                    "PATCH",
                    service["table"],
                    {"id": f"eq.{record_id}"},
                    payload,
                )
            except SupabaseApiError:
                app.logger.exception("Service record update failed for %s", service_key)
                errors = ["Өөрчлөлтийг хадгалж чадсангүй. Supabase тохиргоо, хүснэгтээ шалгана уу."]
                status_code = 503
            else:
                if updated:
                    flash("Өөрчлөлт амжилттай хадгалагдлаа.", "success")
                    return redirect(url_for("service_list", service_key=service_key))
                abort(404)

    return render_template(
        "service_form.html",
        service=service,
        record=record,
        form_data=form_data,
        errors=errors,
        email=session["user_email"],
        csrf_token=csrf_token(),
        active_section=service["active_section"],
        status_labels=SERVICE_STATUSES,
    ), status_code


@app.route("/services/<service_key>/<int:record_id>/delete", methods=["GET", "POST"])
def service_delete(service_key, record_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    service = service_type_or_404(service_key)
    try:
        record = get_service_record(service, record_id)
    except SupabaseApiError:
        app.logger.exception("Service record lookup failed before delete")
        abort(503, description="Supabase бүртгэлийг ачаалж чадсангүй.")
    if record is None:
        abort(404)

    if request.method == "POST":
        if not valid_csrf_token():
            return "Хүсэлтийн баталгаажуулалт амжилтгүй.", 400
        try:
            deleted = supabase_write(
                "DELETE",
                service["table"],
                {"id": f"eq.{record_id}"},
            )
        except SupabaseApiError:
            app.logger.exception("Service record delete failed for %s", service_key)
            flash("Бүртгэлийг устгаж чадсангүй. Supabase тохиргоогоо шалгана уу.", "error")
        else:
            if not deleted:
                abort(404)
            flash("Бүртгэл устгагдлаа.", "success")
        return redirect(url_for("service_list", service_key=service_key))

    return render_template(
        "service_confirm_delete.html",
        service=service,
        record=record,
        email=session["user_email"],
        csrf_token=csrf_token(),
        active_section=service["active_section"],
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_login()
    if not valid_csrf_token():
        return render_login("Хүсэлтийн баталгаажуулалт амжилтгүй. Дахин оролдоно уу.", 400)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        return render_login("И-мэйл болон нууц үгээ оруулна уу.", 400)

    try:
        users = supabase_get(
            "users",
            {
                "select": "email,password_hash",
                "email": f"eq.{email}",
                "limit": "1",
            },
        )
    except SupabaseApiError:
        app.logger.exception("User lookup failed")
        return render_login(
            "Supabase-тэй холбогдож чадсангүй. Тохиргоогоо шалгана уу.", 503
        )

    user = users[0] if users else None
    password_bytes = password.encode("utf-8")
    password_matches = False
    if user and len(password_bytes) <= 72:
        try:
            password_matches = bcrypt.checkpw(
                password_bytes, user.get("password_hash", "").encode("utf-8")
            )
        except (TypeError, ValueError):
            app.logger.error("Stored password hash is invalid")

    if not password_matches:
        return render_login("И-мэйл эсвэл нууц үг буруу байна.", 401)

    session.clear()
    session.permanent = True
    session["user_email"] = user["email"]
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    if not valid_csrf_token():
        return "Хүсэлтийн баталгаажуулалт амжилтгүй.", 400
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError("SUPABASE_URL болон SUPABASE_SECRET_KEY-ийг .env-д тохируулна уу.")
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
