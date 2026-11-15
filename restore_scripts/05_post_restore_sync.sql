
-- ==============================================================================
-- 5. Post-Restore Data Synchronization & Status Alignment
-- ==============================================================================
-- For QR codes that have an active destination URL set, mark them claimed
UPDATE public.qr_codes
SET password_changed = true,
    requires_setup_code = false
WHERE destination_url IS NOT NULL AND length(trim(destination_url)) > 0;

-- Verification summary query
SELECT 'batches' AS table_name, COUNT(*) AS total_rows FROM public.batches
UNION ALL
SELECT 'qr_codes (total)' AS table_name, COUNT(*) AS total_rows FROM public.qr_codes
UNION ALL
SELECT 'qr_codes (active links)' AS table_name, COUNT(*) AS total_rows FROM public.qr_codes WHERE destination_url IS NOT NULL
UNION ALL
SELECT 'qr_password_attempts' AS table_name, COUNT(*) AS total_rows FROM public.qr_password_attempts;
