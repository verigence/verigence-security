-- Verigence Security v2 (0054): an announcement may carry one image (a poster, a graphic), product owner
-- 6 Nov 2026. The image is kept in the database (at most 2 MB, PNG/JPEG/WebP/GIF); the apps fetch it
-- by the announcement's id. A graphic can stand on its own, so the text body may now be empty.
-- Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.announcement_images (
  announcement_id uuid PRIMARY KEY
    REFERENCES security.announcements(announcement_id) ON DELETE CASCADE,
  content_type text NOT NULL CHECK (content_type IN ('image/png','image/jpeg','image/webp','image/gif')),
  data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 2097152),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  width integer CHECK (width IS NULL OR width > 0),
  height integer CHECK (height IS NULL OR height > 0),
  uploaded_by_user_id uuid NOT NULL,
  uploaded_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE security.announcements DROP CONSTRAINT IF EXISTS announcements_body_check;
ALTER TABLE security.announcements
  ADD CONSTRAINT announcements_body_check CHECK (length(body) BETWEEN 0 AND 1000);

COMMIT;
