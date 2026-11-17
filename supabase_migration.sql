ALTER TABLE public.content_drafts
    DROP CONSTRAINT IF EXISTS content_drafts_status_check;

ALTER TABLE public.content_drafts
    ADD CONSTRAINT content_drafts_status_check
    CHECK (status IN ('draft', 'published', 'rejected'));
