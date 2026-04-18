ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS password_reset_required boolean NOT NULL DEFAULT false;

UPDATE public.users
SET password_reset_required = true
WHERE password_hash IS NOT NULL
  AND password_hash !~ '^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$';
