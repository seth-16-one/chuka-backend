ALTER TABLE public.registration
ALTER COLUMN approved SET DEFAULT true;

UPDATE public.registration
SET approved = true,
    approved_at = COALESCE(approved_at, NOW())
WHERE approved IS DISTINCT FROM true;
