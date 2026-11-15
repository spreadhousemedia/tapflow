-- ==============================================================================
-- TAPFLOW / SPREAD NFC COMPLETE DATABASE & BACKUP RESTORE SCRIPT
-- Restores Tables, RPC Functions, Extensions, Indexes, 12 Batches, 2,072 QR Codes
-- Run this in Supabase Dashboard -> SQL Editor -> New Query -> Run
-- ==============================================================================

-- ==============================================================================
-- SPREAD NFC HIGH-PERFORMANCE DATABASE SCHEMA & STORED PROCEDURES
-- Optimized for instant query execution, Trigram indexing, and batch creation
-- ==============================================================================

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- 2. Create Batches Table
CREATE TABLE IF NOT EXISTS public.batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_name TEXT NOT NULL,
    series_prefix TEXT NOT NULL,
    start_number TEXT NOT NULL,
    end_number TEXT NOT NULL,
    total_qr_codes INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. Create QR Codes Table
CREATE TABLE IF NOT EXISTS public.qr_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_number TEXT NOT NULL UNIQUE,
    qr_name TEXT NOT NULL,
    destination_url TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    batch_id UUID REFERENCES public.batches(id) ON DELETE SET NULL,
    password_hash TEXT NOT NULL,
    password_changed BOOLEAN NOT NULL DEFAULT false,
    claimed_at TIMESTAMPTZ DEFAULT NULL,
    owner_email TEXT DEFAULT NULL,
    requires_setup_code BOOLEAN NOT NULL DEFAULT true,
    scan_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Migration Helper for Existing Databases (safe idempotent adds)
ALTER TABLE public.qr_codes
    ADD COLUMN IF NOT EXISTS password_changed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS owner_email TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS requires_setup_code BOOLEAN NOT NULL DEFAULT true;

-- 3B. Rate Limiting Table (Protects against brute-force guessing of setup codes / passwords)
CREATE TABLE IF NOT EXISTS public.qr_rate_limits (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ DEFAULT NULL
);

-- 4. High-Speed Indexes (Sub-10ms lookup, sorting, and Trigram search)
CREATE INDEX IF NOT EXISTS idx_qr_codes_qr_number ON public.qr_codes(qr_number);
CREATE INDEX IF NOT EXISTS idx_qr_codes_created_at ON public.qr_codes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_qr_codes_batch_id ON public.qr_codes(batch_id);
CREATE INDEX IF NOT EXISTS idx_qr_codes_status ON public.qr_codes(status);
CREATE INDEX IF NOT EXISTS idx_qr_codes_destination_url ON public.qr_codes(destination_url) WHERE destination_url IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_batches_created_at ON public.batches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_batches_batch_name ON public.batches(batch_name);

-- Covering Index: Index-Only Scan for scanner redirect path (blazing fast)
CREATE INDEX IF NOT EXISTS idx_qr_codes_scan_covering
    ON public.qr_codes (qr_number, status)
    INCLUDE (destination_url, password_changed);

-- GIN Trigram Index: Accelerates 'ilike %search%' substring queries by 20x-30x
CREATE INDEX IF NOT EXISTS idx_qr_codes_trgm ON public.qr_codes USING gin (
    qr_number gin_trgm_ops,
    qr_name gin_trgm_ops
);

-- ==============================================================================
-- RPC 1: admin_create_single_qr
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.admin_create_single_qr(
    p_qr_number TEXT,
    p_qr_name TEXT,
    p_destination_url TEXT DEFAULT NULL,
    p_password TEXT DEFAULT NULL,  -- REQUIRED at application layer, no insecure default
    p_status TEXT DEFAULT 'active'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
    v_pass_hash TEXT;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));

    IF v_norm_qr IS NULL OR length(v_norm_qr) = 0 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'invalid_qr_number');
    END IF;

    -- Enforce minimum password length at DB layer
    IF p_password IS NULL OR length(p_password) < 4 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'password_too_short');
    END IF;

    IF EXISTS (SELECT 1 FROM public.qr_codes WHERE qr_number = v_norm_qr) THEN
        RETURN jsonb_build_object('ok', false, 'error', 'duplicate_qr_number');
    END IF;

    v_pass_hash := crypt(p_password, gen_salt('bf', 8));

    INSERT INTO public.qr_codes (
        qr_number,
        qr_name,
        destination_url,
        password_hash,
        status
    ) VALUES (
        v_norm_qr,
        TRIM(p_qr_name),
        NULLIF(TRIM(p_destination_url), ''),
        v_pass_hash,
        COALESCE(p_status, 'active')
    );

    RETURN jsonb_build_object('ok', true, 'qr_number', v_norm_qr);
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('ok', false, 'error', SQLERRM);
END;
$$;

-- ==============================================================================
-- RPC 2: admin_create_batch
-- Blazing-fast set-based bulk generator using generate_series
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.admin_create_batch(
    p_batch_name TEXT,
    p_series_prefix TEXT,
    p_start_number TEXT,
    p_end_number TEXT,
    p_password_mode TEXT DEFAULT 'common',
    p_common_password TEXT DEFAULT NULL,
    p_default_url TEXT DEFAULT NULL,
    p_dry_run BOOLEAN DEFAULT true
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_start INT;
    v_end INT;
    v_pad_len INT;
    v_total INT;
    v_prefix TEXT;
    v_first TEXT;
    v_last TEXT;
    v_conflicts TEXT[];
    v_batch_id UUID;
    v_common_hash TEXT;
    v_passwords JSONB := '[]'::jsonb;
BEGIN
    v_start := p_start_number::INT;
    v_end := p_end_number::INT;
    v_pad_len := length(p_start_number);
    v_total := (v_end - v_start) + 1;
    v_prefix := UPPER(TRIM(p_series_prefix));

    IF v_total <= 0 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'start_after_end');
    END IF;

    IF v_total > 5000 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'range_too_large');
    END IF;

    v_first := v_prefix || lpad(v_start::TEXT, v_pad_len, '0');
    v_last := v_prefix || lpad(v_end::TEXT, v_pad_len, '0');

    -- Fast Set-Based Duplicate Conflict Check
    SELECT array_agg(q.qr_number)
    INTO v_conflicts
    FROM (
        SELECT v_prefix || lpad(s::TEXT, v_pad_len, '0') AS qr_num
        FROM generate_series(v_start, v_end) s
    ) gen
    JOIN public.qr_codes q ON q.qr_number = gen.qr_num;

    IF v_conflicts IS NOT NULL AND array_length(v_conflicts, 1) > 0 THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'duplicates',
            'conflicts', to_jsonb(v_conflicts)
        );
    END IF;

    -- If this is a preview dry-run, return range summary immediately
    IF p_dry_run THEN
        RETURN jsonb_build_object(
            'ok', true,
            'total', v_total,
            'first', v_first,
            'last', v_last
        );
    END IF;

    -- Create Batch Record
    INSERT INTO public.batches (
        batch_name,
        series_prefix,
        start_number,
        end_number,
        total_qr_codes
    ) VALUES (
        TRIM(p_batch_name),
        v_prefix,
        p_start_number,
        p_end_number,
        v_total
    ) RETURNING id INTO v_batch_id;

    -- High-speed set-based bulk insert into qr_codes
    IF p_password_mode = 'common' THEN
        -- Enforce minimum password for common mode
        IF p_common_password IS NULL OR length(p_common_password) < 4 THEN
            RETURN jsonb_build_object('ok', false, 'error', 'password_too_short');
        END IF;
        v_common_hash := crypt(p_common_password, gen_salt('bf', 8));

        INSERT INTO public.qr_codes (
            qr_number,
            qr_name,
            destination_url,
            status,
            batch_id,
            password_hash
        )
        SELECT
            v_prefix || lpad(s::TEXT, v_pad_len, '0'),
            TRIM(p_batch_name) || ' #' || s::TEXT,
            NULLIF(TRIM(p_default_url), ''),
            'active',
            v_batch_id,
            v_common_hash
        FROM generate_series(v_start, v_end) s;

        RETURN jsonb_build_object(
            'ok', true,
            'batch_id', v_batch_id,
            'total', v_total,
            'password_mode', 'common'
        );
    ELSE
        -- Unique passwords per QR: generate random keys in bulk
        WITH generated_rows AS (
            SELECT
                v_prefix || lpad(s::TEXT, v_pad_len, '0') AS num,
                TRIM(p_batch_name) || ' #' || s::TEXT AS name,
                substr(md5(random()::text || s::text), 1, 6) AS plain_pwd
            FROM generate_series(v_start, v_end) s
        ),
        inserted_rows AS (
            INSERT INTO public.qr_codes (
                qr_number,
                qr_name,
                destination_url,
                status,
                batch_id,
                password_hash
            )
            SELECT
                num,
                name,
                NULLIF(TRIM(p_default_url), ''),
                'active',
                v_batch_id,
                crypt(plain_pwd, gen_salt('bf', 8))
            FROM generated_rows
            RETURNING qr_number
        )
        SELECT jsonb_agg(jsonb_build_object('qr_number', num, 'password', plain_pwd))
        INTO v_passwords
        FROM generated_rows;

        RETURN jsonb_build_object(
            'ok', true,
            'batch_id', v_batch_id,
            'total', v_total,
            'password_mode', 'unique',
            'passwords', v_passwords
        );
    END IF;

EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('ok', false, 'error', SQLERRM);
END;
$$;

-- ==============================================================================
-- RPC 3: admin_process_qr_csv
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.admin_process_qr_csv(
    p_rows JSONB,
    p_dry_run BOOLEAN DEFAULT true
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_row JSONB;
    v_qr_num TEXT;
    v_qr_name TEXT;
    v_url TEXT;
    v_pwd TEXT;
    v_errors JSONB := '[]'::jsonb;
    v_valid_count INT := 0;
    v_created_count INT := 0;
    v_idx INT := 0;
    v_seen_in_file TEXT[] := '{}';
BEGIN
    FOR v_row IN SELECT * FROM jsonb_array_elements(p_rows)
    LOOP
        v_idx := v_idx + 1;
        v_qr_num := UPPER(TRIM(COALESCE(v_row->>'qr_number', '')));
        v_qr_name := TRIM(COALESCE(v_row->>'qr_name', ''));
        v_url := NULLIF(TRIM(COALESCE(v_row->>'destination_url', '')), '');
        v_pwd := COALESCE(v_row->>'password', '');

        IF v_qr_num = '' THEN
            v_errors := v_errors || jsonb_build_object('row', v_idx, 'error', 'missing_qr_number');
            CONTINUE;
        END IF;

        IF v_qr_num = ANY(v_seen_in_file) THEN
            v_errors := v_errors || jsonb_build_object('row', v_idx, 'qr_number', v_qr_num, 'error', 'duplicate_in_file');
            CONTINUE;
        END IF;

        v_seen_in_file := array_append(v_seen_in_file, v_qr_num);

        IF EXISTS (SELECT 1 FROM public.qr_codes WHERE qr_number = v_qr_num) THEN
            v_errors := v_errors || jsonb_build_object('row', v_idx, 'qr_number', v_qr_num, 'error', 'already_exists');
            CONTINUE;
        END IF;

        IF length(v_pwd) < 4 THEN
            v_errors := v_errors || jsonb_build_object('row', v_idx, 'qr_number', v_qr_num, 'error', 'invalid_password');
            CONTINUE;
        END IF;

        v_valid_count := v_valid_count + 1;

        IF NOT p_dry_run THEN
            INSERT INTO public.qr_codes (
                qr_number,
                qr_name,
                destination_url,
                password_hash,
                status
            ) VALUES (
                v_qr_num,
                CASE WHEN v_qr_name = '' THEN v_qr_num ELSE v_qr_name END,
                v_url,
                crypt(v_pwd, gen_salt('bf', 8)),
                'active'
            );
            v_created_count := v_created_count + 1;
        END IF;
    END LOOP;

    RETURN jsonb_build_object(
        'ok', true,
        'total', v_idx,
        'valid_count', v_valid_count,
        'error_count', jsonb_array_length(v_errors),
        'errors', v_errors,
        'created', v_created_count
    );
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('ok', false, 'error', SQLERRM);
END;
$$;

-- ==============================================================================
-- RPC 4: admin_reset_qr_password
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.admin_reset_qr_password(
    p_qr_id UUID,
    p_new_password TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF p_new_password IS NULL OR length(p_new_password) < 4 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'password_too_short');
    END IF;

    UPDATE public.qr_codes
    SET password_hash = crypt(p_new_password, gen_salt('bf', 8)),
        updated_at = now()
    WHERE id = p_qr_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    RETURN jsonb_build_object('ok', true);
END;
$$;

-- ==============================================================================
-- RPC 4B: admin_reset_qr_unclaimed (Reset QR back to Unclaimed with Setup Code)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.admin_reset_qr_unclaimed(
    p_qr_id UUID,
    p_new_setup_code TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF p_new_setup_code IS NULL OR length(p_new_setup_code) < 4 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'password_too_short');
    END IF;

    UPDATE public.qr_codes
    SET password_hash = crypt(TRIM(p_new_setup_code), gen_salt('bf', 8)),
        password_changed = false,
        claimed_at = NULL,
        owner_email = NULL,
        updated_at = now()
    WHERE id = p_qr_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    RETURN jsonb_build_object('ok', true);
END;
$$;

-- ==============================================================================
-- Rate Limiting Helpers (brute-force protection for setup codes and passwords)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.check_and_record_rate_limit(
    p_key TEXT,
    p_max_attempts INT DEFAULT 5,
    p_window_seconds INT DEFAULT 300,
    p_lockout_seconds INT DEFAULT 300
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec RECORD;
BEGIN
    SELECT attempts, last_attempt, locked_until
    INTO v_rec
    FROM public.qr_rate_limits
    WHERE key = p_key;

    -- Check if currently locked out
    IF v_rec IS NOT NULL AND v_rec.locked_until IS NOT NULL AND v_rec.locked_until > now() THEN
        RETURN false;
    END IF;

    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.record_failed_rate_limit(
    p_key TEXT,
    p_max_attempts INT DEFAULT 5,
    p_window_seconds INT DEFAULT 300,
    p_lockout_seconds INT DEFAULT 300
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec RECORD;
BEGIN
    SELECT attempts, last_attempt, locked_until
    INTO v_rec
    FROM public.qr_rate_limits
    WHERE key = p_key;

    IF v_rec IS NULL THEN
        INSERT INTO public.qr_rate_limits (key, attempts, last_attempt)
        VALUES (p_key, 1, now())
        ON CONFLICT (key) DO UPDATE
        SET attempts = 1, last_attempt = now(), locked_until = NULL;
    ELSIF v_rec.last_attempt < now() - (p_window_seconds || ' seconds')::interval THEN
        UPDATE public.qr_rate_limits
        SET attempts = 1, last_attempt = now(), locked_until = NULL
        WHERE key = p_key;
    ELSIF v_rec.attempts + 1 >= p_max_attempts THEN
        UPDATE public.qr_rate_limits
        SET attempts = v_rec.attempts + 1,
            last_attempt = now(),
            locked_until = now() + (p_lockout_seconds || ' seconds')::interval
        WHERE key = p_key;
    ELSE
        UPDATE public.qr_rate_limits
        SET attempts = v_rec.attempts + 1, last_attempt = now()
        WHERE key = p_key;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.clear_rate_limit(p_key TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM public.qr_rate_limits WHERE key = p_key;
END;
$$;

-- ==============================================================================
-- RPC 5: request_qr_update (Public Standee Setup & Claim Status Check)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.request_qr_update(
    p_qr_number TEXT,
    p_new_url TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
    v_status TEXT;
    v_is_claimed BOOLEAN;
    v_dest TEXT;
    v_email TEXT;
    v_req_setup BOOLEAN;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));

    SELECT status, password_changed, destination_url, owner_email, COALESCE(requires_setup_code, true)
    INTO v_status, v_is_claimed, v_dest, v_email, v_req_setup
    FROM public.qr_codes
    WHERE qr_number = v_norm_qr;

    IF v_status IS NULL THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    IF v_status != 'active' THEN
        RETURN jsonb_build_object('ok', false, 'error', 'inactive');
    END IF;

    -- A card is considered claimed only if password_changed is true AND a destination URL has been set
    RETURN jsonb_build_object(
        'ok', true,
        'is_claimed', (COALESCE(v_is_claimed, false) AND v_dest IS NOT NULL AND length(trim(v_dest)) > 0),
        'destination_url', v_dest,
        'qr_number', v_norm_qr,
        'owner_email', v_email,
        'requires_setup_code', v_req_setup
    );
END;
$$;

-- ==============================================================================
-- RPC 5B: verify_setup_code (Scenario C Step 1: Validate Packaging Code)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.verify_setup_code(
    p_qr_number TEXT,
    p_setup_code TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
    v_hash TEXT;
    v_is_claimed BOOLEAN;
    v_status TEXT;
    v_req_setup BOOLEAN;
    v_rate_key TEXT;
    v_allowed BOOLEAN;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));
    v_rate_key := 'setup_verify_' || v_norm_qr;

    -- Check Rate Limiter (Max 5 attempts per 5 minutes)
    v_allowed := public.check_and_record_rate_limit(v_rate_key, 5, 300, 300);
    IF NOT v_allowed THEN
        RETURN jsonb_build_object('ok', false, 'error', 'too_many_attempts');
    END IF;

    SELECT password_hash, password_changed, status, COALESCE(requires_setup_code, true)
    INTO v_hash, v_is_claimed, v_status, v_req_setup
    FROM public.qr_codes
    WHERE qr_number = v_norm_qr;

    IF v_hash IS NULL THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    IF v_status != 'active' THEN
        RETURN jsonb_build_object('ok', false, 'error', 'inactive');
    END IF;

    IF v_is_claimed IS TRUE THEN
        RETURN jsonb_build_object('ok', false, 'error', 'already_claimed');
    END IF;

    -- If this card is in Open Mode (Scenario B), setup code is not required
    IF v_req_setup IS FALSE THEN
        RETURN jsonb_build_object('ok', true, 'requires_setup_code', false);
    END IF;

    -- Verify setup code against current packaging hash
    IF v_hash != crypt(TRIM(p_setup_code), v_hash) AND v_hash != crypt(UPPER(TRIM(p_setup_code)), v_hash) THEN
        PERFORM public.record_failed_rate_limit(v_rate_key, 5, 300, 300);
        RETURN jsonb_build_object('ok', false, 'error', 'wrong_setup_code');
    END IF;

    -- Success: clear rate limit
    PERFORM public.clear_rate_limit(v_rate_key);
    RETURN jsonb_build_object('ok', true, 'requires_setup_code', true);
END;
$$;

-- ==============================================================================
-- RPC 5C: customer_claim_qr (Atomic Claim & Password Creation for Scenario B and C)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.customer_claim_qr(
    p_qr_number TEXT,
    p_setup_code TEXT DEFAULT NULL,
    p_new_password TEXT DEFAULT NULL,
    p_destination_url TEXT DEFAULT NULL,
    p_owner_email TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
    v_hash TEXT;
    v_is_claimed BOOLEAN;
    v_status TEXT;
    v_req_setup BOOLEAN;
    v_rate_key TEXT;
    v_allowed BOOLEAN;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));
    v_rate_key := 'claim_' || v_norm_qr;

    -- Check Rate Limiter
    v_allowed := public.check_and_record_rate_limit(v_rate_key, 5, 300, 300);
    IF NOT v_allowed THEN
        RETURN jsonb_build_object('ok', false, 'error', 'too_many_attempts');
    END IF;

    -- Row-Level Lock: Prevents simultaneous race conditions (only 1 claim will ever succeed)
    SELECT password_hash, password_changed, status, COALESCE(requires_setup_code, true)
    INTO v_hash, v_is_claimed, v_status, v_req_setup
    FROM public.qr_codes
    WHERE qr_number = v_norm_qr
    FOR UPDATE;

    IF v_hash IS NULL THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    IF v_status != 'active' THEN
        RETURN jsonb_build_object('ok', false, 'error', 'inactive');
    END IF;

    IF v_is_claimed IS TRUE THEN
        RETURN jsonb_build_object('ok', false, 'error', 'already_claimed');
    END IF;

    -- If this card requires a packaging setup code (Scenario C), verify it securely
    IF v_req_setup IS TRUE THEN
        IF p_setup_code IS NULL OR length(trim(p_setup_code)) = 0 THEN
            RETURN jsonb_build_object('ok', false, 'error', 'missing_setup_code');
        END IF;

        IF v_hash != crypt(TRIM(p_setup_code), v_hash) AND v_hash != crypt(UPPER(TRIM(p_setup_code)), v_hash) THEN
            PERFORM public.record_failed_rate_limit(v_rate_key, 5, 300, 300);
            RETURN jsonb_build_object('ok', false, 'error', 'wrong_setup_code');
        END IF;
    END IF;

    -- Enforce minimum password length
    IF p_new_password IS NULL OR length(p_new_password) < 4 THEN
        RETURN jsonb_build_object('ok', false, 'error', 'password_too_short');
    END IF;

    -- Clear rate limit upon success
    PERFORM public.clear_rate_limit(v_rate_key);

    -- IMPORTANT: qr_number is PERMANENT and NEVER changed. Only destination_url, password_hash, claimed_at updated!
    UPDATE public.qr_codes
    SET password_hash = crypt(p_new_password, gen_salt('bf', 8)),
        password_changed = true,
        claimed_at = now(),
        destination_url = NULLIF(TRIM(p_destination_url), ''),
        owner_email = NULLIF(TRIM(p_owner_email), ''),
        updated_at = now()
    WHERE qr_number = v_norm_qr;

    RETURN jsonb_build_object('ok', true, 'qr_number', v_norm_qr);
END;
$$;

-- ==============================================================================
-- RPC 6: confirm_qr_update (Update Existing Destination with Password Verification)
-- ==============================================================================
CREATE OR REPLACE FUNCTION public.confirm_qr_update(
    p_qr_number TEXT,
    p_new_url TEXT,
    p_password TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
    v_hash TEXT;
    v_rate_key TEXT;
    v_allowed BOOLEAN;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));
    v_rate_key := 'update_' || v_norm_qr;

    -- Check Rate Limiter
    v_allowed := public.check_and_record_rate_limit(v_rate_key, 5, 300, 300);
    IF NOT v_allowed THEN
        RETURN jsonb_build_object('ok', false, 'error', 'too_many_attempts');
    END IF;

    -- Row-Level Lock
    SELECT password_hash INTO v_hash
    FROM public.qr_codes
    WHERE qr_number = v_norm_qr AND status = 'active'
    FOR UPDATE;

    IF v_hash IS NULL THEN
        RETURN jsonb_build_object('ok', false, 'error', 'not_found');
    END IF;

    IF v_hash != crypt(p_password, v_hash) THEN
        PERFORM public.record_failed_rate_limit(v_rate_key, 5, 300, 300);
        RETURN jsonb_build_object('ok', false, 'error', 'wrong_password');
    END IF;

    -- Clear rate limit on success
    PERFORM public.clear_rate_limit(v_rate_key);

    -- CRITICAL: qr_number is NEVER modified! Only destination_url is updated.
    UPDATE public.qr_codes
    SET destination_url = TRIM(p_new_url),
        updated_at = now()
    WHERE qr_number = v_norm_qr;

    RETURN jsonb_build_object('ok', true);
END;
$$;

-- ==============================================================================
-- RPC 7: get_qr_redirect (Blazing-Fast Scanner Redirection, High Concurrency)
-- Note: Advisory locks removed to allow thousands of concurrent scans per second
-- ==============================================================================
DROP FUNCTION IF EXISTS public.get_qr_redirect(TEXT);
CREATE OR REPLACE FUNCTION public.get_qr_redirect(
    p_qr_number TEXT
)
RETURNS TABLE (
    status TEXT,
    destination_url TEXT,
    is_claimed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_norm_qr TEXT;
BEGIN
    v_norm_qr := UPPER(TRIM(p_qr_number));

    -- Fast atomic scan counter increment (no advisory lock needed — UPDATE is inherently atomic)
    UPDATE public.qr_codes
    SET scan_count = scan_count + 1
    WHERE qr_number = v_norm_qr;

    RETURN QUERY
    SELECT q.status, q.destination_url,
           (q.password_changed AND q.destination_url IS NOT NULL AND length(trim(q.destination_url)) > 0) AS is_claimed
    FROM public.qr_codes q
    WHERE q.qr_number = v_norm_qr;
END;
$$;

-- ==============================================================================
-- 8. Grants and Permissions (Ensures client can invoke RPCs without permission errors)
-- ==============================================================================
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role;

-- Rate limits table grants
GRANT ALL ON public.qr_rate_limits TO anon, authenticated, service_role;

-- Row Level Security (RLS) Setup
ALTER TABLE public.qr_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.batches ENABLE ROW LEVEL SECURITY;

-- PUBLIC: Allow anon read for QR scan redirect (get_qr_redirect RPC uses SECURITY DEFINER)
DROP POLICY IF EXISTS "Public QR Read" ON public.qr_codes;
CREATE POLICY "Public QR Read" ON public.qr_codes FOR SELECT USING (true);

-- PUBLIC: Prohibit direct insert/update/delete by anon — all mutations go through SECURITY DEFINER RPCs
DROP POLICY IF EXISTS "Public QR Insert/Update/Delete" ON public.qr_codes;
-- (No policy = denied by default for non-SELECT)

-- AUTHENTICATED ADMIN: Full access to qr_codes table
DROP POLICY IF EXISTS "Admin QR All" ON public.qr_codes;
CREATE POLICY "Admin QR All" ON public.qr_codes FOR ALL USING (auth.role() = 'authenticated');

DROP POLICY IF EXISTS "Batches Read" ON public.batches;
CREATE POLICY "Batches Read" ON public.batches FOR SELECT USING (true);

-- AUTHENTICATED ADMIN: Full access to batches
DROP POLICY IF EXISTS "Batches All" ON public.batches;
CREATE POLICY "Batches All" ON public.batches FOR ALL USING (auth.role() = 'authenticated');

-- ==============================================================================
-- 9. PRODUCTS TABLE (Managed via Admin Panel, displayed on /products)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    short_description TEXT,
    full_description TEXT,
    category TEXT NOT NULL CHECK (category IN ('cards', 'standees', 'tags', 'accessories', 'bundles')),
    material TEXT NOT NULL,
    chip_type TEXT NOT NULL DEFAULT 'NTAG216',
    base_price NUMERIC(10, 2) NOT NULL,
    sale_price NUMERIC(10, 2),
    images TEXT[] NOT NULL DEFAULT '{}',
    features TEXT[] NOT NULL DEFAULT '{}',
    colors JSONB NOT NULL DEFAULT '[]'::jsonb,
    preview_gradient TEXT DEFAULT 'from-zinc-900 via-zinc-800 to-black',
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_featured BOOLEAN NOT NULL DEFAULT false,
    stock_status TEXT NOT NULL DEFAULT 'in_stock' CHECK (stock_status IN ('in_stock', 'low_stock', 'pre_order', 'out_of_stock')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 10. ORDERS TABLE (Created on Website, managed in Admin Panel)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_number TEXT NOT NULL UNIQUE,
    customer_name TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    product_id TEXT,
    product_title TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price NUMERIC(10, 2) NOT NULL,
    discount_amount NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
    total_amount NUMERIC(10, 2) NOT NULL,
    cardholder_name TEXT,
    company_name TEXT,
    destination_url TEXT,
    custom_finish TEXT,
    payment_status TEXT NOT NULL DEFAULT 'pending' CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded')),
    order_status TEXT NOT NULL DEFAULT 'pending_verification' CHECK (
        order_status IN ('pending_verification', 'in_production', 'quality_checked', 'shipped', 'delivered', 'cancelled')
    ),
    courier_partner TEXT,
    courier_tracking_number TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 11. SUPPORT TICKETS TABLE (Submitted on /support, managed in Admin Panel)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.support_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_number TEXT NOT NULL UNIQUE,
    customer_name TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    customer_phone TEXT,
    category TEXT NOT NULL CHECK (
        category IN ('nfc_hardware', 'qr_redirect', 'order_status', 'print_defect', 'password_reset', 'bulk_inquiry', 'general')
    ),
    associated_qr_number TEXT,
    associated_order_number TEXT,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    attachment_urls TEXT[] DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'waiting_customer', 'resolved', 'closed')),
    priority TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'medium', 'high', 'urgent')),
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- 12. CONTACT INQUIRIES TABLE (Submitted on /contact, managed in Admin Panel)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.contact_inquiries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    company TEXT,
    team_size TEXT,
    inquiry_type TEXT,
    card_volume INTEGER DEFAULT 25,
    estimated_quote NUMERIC(10, 2) DEFAULT 0,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'proposal_sent', 'closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS and Grants for New Tables
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contact_inquiries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public Products Read" ON public.products;
CREATE POLICY "Public Products Read" ON public.products FOR SELECT USING (true);
DROP POLICY IF EXISTS "Admin Products All" ON public.products;
CREATE POLICY "Admin Products All" ON public.products FOR ALL USING (true);

DROP POLICY IF EXISTS "Public Orders Insert" ON public.orders;
CREATE POLICY "Public Orders Insert" ON public.orders FOR INSERT WITH CHECK (true);
DROP POLICY IF EXISTS "Public Orders Read" ON public.orders;
CREATE POLICY "Public Orders Read" ON public.orders FOR SELECT USING (true);
DROP POLICY IF EXISTS "Admin Orders All" ON public.orders;
CREATE POLICY "Admin Orders All" ON public.orders FOR ALL USING (true);

DROP POLICY IF EXISTS "Public Support Tickets Insert" ON public.support_tickets;
CREATE POLICY "Public Support Tickets Insert" ON public.support_tickets FOR INSERT WITH CHECK (true);
DROP POLICY IF EXISTS "Public Support Tickets Read" ON public.support_tickets;
CREATE POLICY "Public Support Tickets Read" ON public.support_tickets FOR SELECT USING (true);
DROP POLICY IF EXISTS "Admin Support Tickets All" ON public.support_tickets;
CREATE POLICY "Admin Support Tickets All" ON public.support_tickets FOR ALL USING (true);

DROP POLICY IF EXISTS "Public Inquiries Insert" ON public.contact_inquiries;
CREATE POLICY "Public Inquiries Insert" ON public.contact_inquiries FOR INSERT WITH CHECK (true);
DROP POLICY IF EXISTS "Admin Inquiries All" ON public.contact_inquiries;
CREATE POLICY "Admin Inquiries All" ON public.contact_inquiries FOR ALL USING (true);

GRANT ALL ON public.products TO anon, authenticated, service_role;
GRANT ALL ON public.orders TO anon, authenticated, service_role;
GRANT ALL ON public.support_tickets TO anon, authenticated, service_role;
GRANT ALL ON public.contact_inquiries TO anon, authenticated, service_role;



-- ==============================================================================
-- 13. ADMIN USERS TABLE (Role-Based Access Management)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('super_admin', 'admin', 'manager')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admin_users_email ON public.admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON public.admin_users(role);

ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Admin Users Full Access" ON public.admin_users;
CREATE POLICY "Admin Users Full Access" ON public.admin_users FOR ALL USING (auth.role() = 'authenticated');

GRANT ALL ON public.admin_users TO anon, authenticated, service_role;


-- ==============================================================================
-- 3C. Historical Password Attempts Log Table
-- ==============================================================================
CREATE TABLE IF NOT EXISTS public.qr_password_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_number TEXT NOT NULL,
    success BOOLEAN NOT NULL DEFAULT false,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_qr_password_attempts_qr_number ON public.qr_password_attempts(qr_number);
CREATE INDEX IF NOT EXISTS idx_qr_password_attempts_attempted_at ON public.qr_password_attempts(attempted_at DESC);
ALTER TABLE public.qr_password_attempts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Admin Password Attempts All" ON public.qr_password_attempts;
CREATE POLICY "Admin Password Attempts All" ON public.qr_password_attempts FOR ALL USING (auth.role() = 'authenticated');
GRANT ALL ON public.qr_password_attempts TO anon, authenticated, service_role;


-- ==============================================================================
-- RESTORING BACKUP DATA (BATCHES)
-- ==============================================================================
-- Step 2: Restore Batches (12 records)
INSERT INTO public.batches (id, batch_name, series_prefix, start_number, end_number, total_qr_codes, created_at, updated_at) VALUES
  ('192b512b-f822-44bb-8943-824dcc0b12f2', '77', 'TF', '1', '10', 10, '2026-09-30 18:31:15.534021+00', '2026-10-12 04:14:10.857465+00'),
  ('2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', 'tapflow 1', 'TAP', '001', '250', 250, '2026-09-30 18:44:26.177898+00', '2026-10-12 04:14:10.857465+00'),
  ('3a29dff7-dd62-4bd0-9451-688ee3c3e53e', 'Spread Batch 0-300', 'SP', '1', '300', 300, '2026-10-07 07:41:11.844501+00', '2026-10-12 04:14:10.857465+00'),
  ('4232b215-4e23-4ab2-b390-595c5863e44b', 'September Restaurant Batch', 'T', '001', '301', 301, '2026-09-28 15:07:27.989995+00', '2026-10-12 04:14:10.857465+00'),
  ('52018480-1af0-463f-972d-e815d8b1e593', 'Tapnow', 'TN', '1', '25', 25, '2026-10-10 14:31:37.779764+00', '2026-10-12 04:14:10.857465+00'),
  ('5a0634b5-2930-4b33-b36d-cf042a73d036', 'Tapflow 2', 'TFF', '1', '500', 500, '2026-10-11 14:09:32.911804+00', '2026-10-12 04:14:10.857465+00'),
  ('709d74da-b1f9-48a6-ad43-d7de53794efb', 'SP300-400', 'SP', '301', '500', 200, '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('76284655-1682-4a63-9770-91b3b5d18795', 'Tf', 'TF', '01', '50', 50, '2026-09-29 14:59:50.707753+00', '2026-09-29 14:59:50.707753+00'),
  ('854beaf4-248a-4ed3-a327-f5b4a48ae9d7', 'tapflow', 'TAP', '251', '400', 150, '2026-10-01 11:05:05.535345+00', '2026-10-12 04:14:10.857465+00'),
  ('8bb2d3cc-3617-44d5-b796-4de1c99c540b', 'CSV Test Batch', '', '', '', 1, '2026-09-28 17:39:47.050305+00', '2026-09-28 17:39:47.050305+00'),
  ('dab41a5a-91cd-4d9a-8f8b-2f49783eecfc', 'CSV Batch', '', '', '', 2, '2026-09-28 15:08:44.034381+00', '2026-09-28 15:08:44.034381+00'),
  ('f86b039d-12ae-4858-90a0-ad6a8ecfcd06', 'hellooooo', 'MTM', '122', '456', 335, '2026-09-28 17:24:51.126676+00', '2026-10-12 04:14:10.857465+00')
ON CONFLICT (id) DO NOTHING;


-- ==============================================================================
-- RESTORING BACKUP DATA (QR CODES)
-- ==============================================================================
-- Step 3: Restore QR Codes (2,072 records in batches of 200)
INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('0035735b-cb2d-4eeb-a2c8-29ed8a6a9bc0', 'TFF376', 'TFF376', null, '$2a$06$4NrJq48Mw.Y61Fzel17RKODUqErwQt5mpcCYKlnyyeeJTSOi1KQHS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('005aedcf-8d8d-4782-b986-4a6f0bfe3233', 'SP089', 'SP089', null, '$2a$06$VlQuX33aE2n.YrZZt5p7XeBV7LzDFULAXLIQQmQ3/9gD/MMmfd6gS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('00699dbe-bbbe-4108-b2b1-ffaa3001ad91', 'T021', 'T021', null, '$2a$06$/kUjekDuDTeJtc1OoXu3vOtXlSUDJc9OhO6VDvt6ZbuUAbNQEIsgC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('008669f1-bdc8-4462-a8b7-4422ac128137', 'TAP099', 'TAP099', null, '$2a$06$mBz..BroWxohNu8TbEqIeuBZRAxYeAbv2V/zSeqypknepli.fcYXa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0098bc9f-ec56-469b-b26a-1e877e27f91a', 'TAP220', 'TAP220', 'https://search.google.com/local/writereview?placeid=ChIJySN3-DXrDzkREPhtPcJnZYk', '$2a$06$uj.NZ.SgAidwKp/YKdj1E.pvgW10VlCwhFjTXlOh4/3saXwdxPI1q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:48:12.243859+00'),
  ('00aec55c-e597-49d3-95c6-222ad534f150', 'TAP294', 'TAP294', null, '$2a$06$L7b1g97H.UYzB7lODp/oCeT81o/yv2nQVCc49OSTUAi3wSNJEmuzi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0102ca98-a51c-4102-bfb5-0565db4c39d1', 'MTM313', 'MTM313', null, '$2a$06$oUvkm5v0WDy.6JPyeRHo4.OU6z05pSbATx4z5geuxk43XQtga38py', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('01086f02-f950-414f-92a7-ea996e5095bc', 'SP185', 'SP185', null, '$2a$06$p/udxq8lhmZu2T0jXC.Oe.YMrL5ffsYsaucoqjev9g2f21VT4cKpy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0126b1ca-55c3-45dc-b3e1-8c64b6bb5103', 'SP427', 'SP427', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0159f2df-4b74-47ae-bde1-a3c442148e0e', 'SP220', 'SP220', null, '$2a$06$AprCkUy4a2v/.2FH55UnSeiqATpxz4qhHx3BEjpowSpI4tcZfMBsu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('015dfefb-27c0-4895-99a5-bafe4719c72e', 'SP050', 'SP050', null, '$2a$06$R0Zcn5mesCsOkwjoKW/s8.NkYs8rlad1uPscpzYDhFOzF0bjXoFwK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('016f7292-ea2d-4231-b114-5fb5fd86357a', 'SP149', 'SP149', null, '$2a$06$3o7JLWow4XIxPoMvKaP6HubDPQsSLwGtzVE0tPqf/bnSi4VrRsdFy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('017ac200-44d7-4f50-901e-5b5b5e325e50', 'SP481', 'SP481', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('017e6317-84a6-4b64-bfa6-c9a26bb53e08', 'SP415', 'SP415', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0196e3fb-370c-4d25-bf72-a5f800cf57b1', 'SP488', 'SP488', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('02155d88-7f30-425d-a2fa-4f19b43be666', 'TFF410', 'TFF410', null, '$2a$06$wC.7pW.TcNQdGRkjFSK3seUxJvy7kcFfllcBCGUWjq8gUePw2k4V.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0233cf37-631b-4249-a77c-e55d183c46ac', 'TFF006', 'TFF006', null, '$2a$06$3Vf8vFQNOGPLXOCuDmLob.bhtpSIU8f8CxcZQukCj4OFyBduvZI4K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('02631288-3523-4f30-8689-0cc14c8a0fbe', 'TAP092', 'TAP092', null, '$2a$06$8NFgN.YZNxjlTC4O4TXtl.OI8u.zaYlEhsEKv0OnhzDJ5biRm1h8S', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('027fc25f-20f8-41f6-8d1e-976c64b8db6c', 'MTM151', 'MTM151', null, '$2a$06$7/hf7KQjE4GuUQBVmGq4puxgRtsHtWfTyZbmMosk.hFEBw2i0prTK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('02a8e4d9-2b08-4986-b3f8-79e263612ecf', 'TAP160', 'TAP160', 'https://search.google.com/local/writereview?placeid=ChIJfyPsx1PrDzkRV7qHaZApl44', '$2a$06$62UkvKLwHz1XKEc3Gh9KJODfItKSFVVXEfubzhTvCfMNZ31HdqKGe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:07:59.058445+00'),
  ('02af8172-42ac-4daf-a161-2a677a5715f5', 'TFF160', 'TFF160', null, '$2a$06$PCxG1EyaDNgCCgRp3uaNIeXSupTteyj4X.9erf0EcsXkxRdfiup/W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('02b895ec-d826-4493-a854-7d79df894822', 'TAP105', 'TAP105', null, '$2a$06$ZErCrBK6WYITbkkjYu08.eAOrD/l9lC4GGCigMVvC3woQhT4uizBe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('02d1973b-8cf2-4c28-a1c8-2d465ae3eaa4', 'TFF214', 'TFF214', null, '$2a$06$jsUf/IMhi0gZVNZUjycvxePnKq3mZsUdsATnK6VsemVHuQwnKtJH2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('02e80eb9-dd36-4b92-a806-9a814b13b94c', 'SP433', 'SP433', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('037184b2-e579-4831-9aa0-1b331696839c', 'T110', 'T110', null, '$2a$06$vFI8fHWpwxkh808YiC1mtezbnlfScx2uXB1ijEGi2rEtj33cvLnny', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('038cc153-b63d-404d-8917-99c11c3b83dd', 'MTM399', 'MTM399', null, '$2a$06$VbJDHN7dzN9UpLHxYIIFGeEY3FUu/yG19eJQDwxlZDqzn5kPKHgKm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0411b2ae-60d0-4437-a9fd-a2f0e0698def', 'TFF242', 'TFF242', null, '$2a$06$aFlPha8bz8v5DtczL2kftespBk/JFLQbdBw.jLQ8drNXJ4MWWAGRm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('043df64c-0fae-42e5-95bf-01351123ce40', 'SP137', 'SP137', null, '$2a$06$ieys0hOBBTcGgMVZSSH5oeLLRmtuDZmqg3m/Jm8DU4z6pFYpSNe82', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('044ce3e8-f9a1-46ef-9d84-7796fdd73eb8', 'SP132', 'SP132', null, '$2a$06$YXKYxBgmb.Hpe4JDOLZcc.yWkEBLJf2ABQ9xcw3Hi6IFI5RqXSt0y', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('045daad6-d3af-47ac-bfd1-7edca5c962f1', 'TAP233', 'TAP233', 'https://search.google.com/local/writereview?placeid=ChIJOxsq47vrDzkR7qlJsEhtAIY', '$2a$06$.lGcvbmfI0a4I7J0eLBCyupX/DuhjE.fUhUe0nr/JfHIRbWI5j2MW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:59:00.464218+00'),
  ('047f87d9-1a47-4693-b3f5-9dc3b914f7c2', 'T124', 'T124', null, '$2a$06$KxawmR7E3NYTIzPd6FQNPeoX6lERRfZrXg3fUhBA/b0iIWLqJL4xW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('04c1afb1-6bba-42dd-8223-17da1f2cfafe', 'MTM403', 'MTM403', null, '$2a$06$bHQFSalqFumdaFB9J6ONgu1PJ3880zKmiFUp8LW5.Uh94q5vSoX8O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('04e186a8-1a48-431a-aabe-bd4a18bdcc29', 'MTM435', 'MTM435', null, '$2a$06$l7RwfIfdneuYLP4pel4VvOwDR8p2PzfKmaMq2sW0QDCbvFR99iPHK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('053d3fe2-a80b-4626-ac01-26ff073d9127', 'T019', 'T019', null, '$2a$06$9RVbCAiCzXM.mH4Dh2IxfeFRHy22d7Aysl1TB5dU7okW824IFP5Py', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0545298a-c3eb-4adc-af90-ecdbb29c7b6c', 'TFF339', 'TFF339', null, '$2a$06$pmqxMy0SayYihInsJlRvhOgq69442NSLcMACDGMYanm7BIvSTo2S.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('05527b97-a6ae-40c5-a175-9b75d39b4b98', 'MTM346', 'MTM346', null, '$2a$06$h3s9z6I5c5OsH.x7xYwKA.ywcX7Jb2UuAe763ATf96bbaz.6P4XZq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('05687db1-de89-496a-aca6-f8a96056f145', 'MTM138', 'MTM138', null, '$2a$06$eFepRglDO07s6u1XCmuBbOCoW7yftzht2dFHIXaKNk1/g75ZSnMoS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('058a5f36-637b-4e5f-8529-ef79dcdb77e0', 'MTM443', 'MTM443', null, '$2a$06$6FbUAAmJKezR2RxDGtJ17u7OqxnatAM.RuspvSXS5usg5lF5xQS4y', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('059efb49-7ec8-46d0-a499-b5d0751f8c8b', 'SP476', 'SP476', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('05a7833d-902d-4bed-a9a0-e877681dee88', 'SP102', 'SP102', null, '$2a$06$zsmHVsTDARHTTqKHbpdOYOo7I4gIi2yATN.wCvWJ2aC2v/Wcr60Ti', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('05eeba72-590d-446f-9711-7a5569ee92d6', 'T205', 'T205', null, '$2a$06$uGI77jJvaRK2cM5DRCrM1eN9AdBeQ7r562UsMGL6I3LFti7BOW6zu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06243220-006f-46c7-82d4-d15427935c33', 'T115', 'T115', null, '$2a$06$CvD9OiA3gik8UuUsUTM6kupvtdd6tEVyLAZALap6VBQCA3noga442', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06456a91-1879-4618-95c8-75af5967d4b9', 'TAP259', 'TAP259', null, '$2a$06$mQ50roiNlr5GUER114VNSu1t0.zhEXn2Z8oP3oEhhd65WoPcNz0eG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('065a0a7d-9ec1-4800-a5b4-527067c97a6a', 'TAP341', 'TAP341', null, '$2a$06$WzUjnbXXK3pvOVdsnSCAGu.kdztv0I2F3IBpxcQmjdIudxAIbvm.6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0691bdf1-f66f-4085-aeb0-dc12c6b70952', 'SP157', 'SP157', null, '$2a$06$VBblFqR83gVM2ibdCtaTMe9TPGuKsHuFfB..De2f4kqFNP0T5gNtO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('069ff8c8-0dfe-4f38-b562-29646015be5b', 'T264', 'T264', null, '$2a$06$5O4ehMfx3zSDEdZ8KKQXK.rnw7dgkGhJiYbx9KUvT98y9Ylj2nG/y', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06b288b8-0567-492f-80d0-fa2ce8e3fa96', 'TFF365', 'TFF365', null, '$2a$06$rcIVEbXqUkN1Zi1VFcNqVutQ7UYtxyXslHr9S7ANbJli984OmCTqy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06c2da96-e40d-4cfa-91c3-5e07ce2c6a38', 'TAP357', 'TAP357', null, '$2a$06$dhGqsAqhrHIgBsn4HnIiouf1SHVHrDOmxgRTfC6iCGTxpchloK8da', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06dadc47-a6ee-42ea-9482-b69bcc7b9918', 'MTM259', 'MTM259', null, '$2a$06$BC/Mme40D4sTtvt0KyP5q.6dU4apMT6uAE1xzNQdgmiLAZluevzYS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06e51667-be0b-4ba1-acd1-4f01471c3f3d', 'T232', 'T232', null, '$2a$06$dxU3SeeNWYnuuMvdqkuLuueLuP3lU7DIaAIEw8dEzMPZt1yRE.zxK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('06f3fdd8-e1cb-4aff-bb3c-9f9df67d8b87', 'TFF251', 'TFF251', null, '$2a$06$2XhqEcvyv.QgoddCoVac8e1CXwMD9hBrebu4kf9aCGAn0BBBErI4K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07036e0d-78d9-45c8-be67-df29224ff67a', 'MTM233', 'MTM233', null, '$2a$06$KBlFCw773pB2iIFJmdiFCeQQQOzqw5BA96.xG86cbUBz9TWo9sQ2i', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('071cbdc5-05bb-4cf5-bded-4916b696f228', 'T002', 'T002', null, '$2a$06$pwt0JZZIiOiyrylbpmjHMOe4eHng6KUZ2YZh6i.nPtybjbet/7zzC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('075eaf22-ab33-4d5b-8a24-8bb569c264db', 'MTM274', 'MTM274', null, '$2a$06$cpuFSP1iaHvnH97zAaw4n.CjNbkEPC6q9Uxw77ovQyAQ9bewh43wq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0790edc5-588f-4e4e-8e59-c52928315d6f', 'SP052', 'SP052', null, '$2a$06$bx0RF3XJ3FRi1KogFPQ0aO8im/mEQOHttsad4bJgRndHNW6fA2C36', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0794d253-fb38-4c64-805f-4abb6192647d', 'TN07', 'TN07', null, '$2a$06$EsWEX008wJKci09avgS8dumO9bczt4.uUokrdT75shUrvfFK6kLzu', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('079aa90e-c586-416b-911d-421fbb94042a', 'TAP335', 'TAP335', null, '$2a$06$xxPOCBi/v047Z9fhTUY5aOS0U0wpvw6fglZgN1oe68bnejW8DOnj6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07a0520e-f4b9-4f3a-ae39-d963e1e5a04b', 'TAP032', 'TAP032', null, '$2a$06$LDN3oUNhvb/.7ZYO64Hxj.3XO3PyFE39CbjpGK0XoEkgQmd3SUxU2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07c7d871-3154-4ab6-87f3-a3b1ab2e287b', 'TAP353', 'TAP353', null, '$2a$06$1zJtIIHkFmX1tXZKRdf3duhXCFWI7GJ/DprlkDdu7U0Zf8aICSJFW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07cc21f8-c6f4-41e6-82fe-0d807740593f', 'T111', 'T111', null, '$2a$06$dxDaQqtEoLpjZssJZ2G07eUmKOep.3Z4A.itTPU2JHvtI/3kvEQhq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07df3165-52fd-405e-a994-7aa099845c19', 'TAP108', 'TAP108', null, '$2a$06$5mL6npgIBffhEYcbA1rtUubYsp.k1ltDscS3SSrUdu0byMZBhsPLO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('07df4ec6-c429-48d5-8bf0-7226724c9175', 'MTM441', 'MTM441', null, '$2a$06$b2B/.c6jkYa8/2SOG4GNs.kXmhbMixlT7QGvNeJRjS2yB7QZBNzmq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08034d74-516d-4071-a624-0e635c964b9d', 'TFF434', 'TFF434', null, '$2a$06$K/IYMPLq4JvcHdwj.W/MYOuPf.BVOJMFefLx50P6JrAE49nKqOY.K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('081e1ee7-bd81-4eef-a398-37d72623a078', 'TFF165', 'TFF165', null, '$2a$06$rCY6uJe/ImfE/ZgFLB2XUuTKRWELCy.TDTnO21QtMIz2TScSdmJnq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('081fa526-3f55-4249-a5ed-eb116605f333', 'TAP189', 'TAP189', 'https://search.google.com/local/writereview?placeid=ChIJBxck6c7vpzsRtfxMZVsE48M', '$2a$06$mUaqR6QCkKF4TqHqEXN6YugCdJ5Rux1rlXrnQBHUa27pSueFnej7W', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:33:56.179873+00'),
  ('083692a5-8cf1-4e4e-b8b6-c1ff40984414', 'SP420', 'SP420', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0855057a-2014-4f0b-a2cf-97fd04c0a48e', 'TAP355', 'TAP355', null, '$2a$06$2k6T.DHaJf9mSJf3gxViQO3Ta4Ur1CZVzNRjeuplp2Zs2A1ziGqye', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('085a3dc6-bf0b-4f6c-a1c2-a6a657cc5297', 'MTM167', 'MTM167', null, '$2a$06$C/vqUq2oGYenH3hQRnpg7uVYzKRmYEX0lpxf2C4HEcQpSiyYe07xm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08665add-3cb9-4497-bc36-783102b3be5b', 'TFF462', 'TFF462', null, '$2a$06$/fPu.ADXC.3mxHr1YEk6busz5ZNVKnyko1CQtTG1IsOIExHjwWDcm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08a17cc8-4c80-4380-8c2d-8eb45efb6384', 'MTM433', 'MTM433', null, '$2a$06$Z.XMPk972WucdvealTmAnO/fDCN/IXDFq1DrwlLj65gwvD1xJ/nEi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08a35fff-ae1f-4907-bee9-44e13a6ca39c', 'MTM427', 'MTM427', null, '$2a$06$vPr/2fqfNdQVr3PsYt9dSuSpwEyjjtzgr5yluwXPlWH8dQ62ABYMy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08ab2e35-85b6-4536-9d3d-d1daaf515ddc', 'TFF119', 'TFF119', null, '$2a$06$mq95WUsa3fgHeW0nmNwfnudAHl/nf2J6bXSxaST3PopA1YpmrxKui', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08c38d58-0307-4a18-baf6-ef10ca0a4430', 'TFF468', 'TFF468', null, '$2a$06$zoIExEmNsoPxvuJXlwfVTOobko2hYZlm9eDO6lBc4fdVqDkWiTN/W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08c9404c-1ea2-4b38-8b1f-62581ef91c3c', 'TFF205', 'TFF205', null, '$2a$06$yy.0HATAC5IumHTdmQPjbev6xdTroBvpyhx2DguY1IuANBQo3ETEi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08cb8d6f-4dea-45dd-ac38-928aba1dfa6f', 'MTM210', 'MTM210', null, '$2a$06$KdTz5IEdLNDqvHzQ4M2tTufgsgZtEJmrstEzsmE9N/mDbbfCC9vdm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08e43a4f-9579-4485-96f3-e1024b435253', 'SP485', 'SP485', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('08f0fee7-12fe-4dc3-b021-ad45d4dcfb9c', 'T063', 'T063', null, '$2a$06$aBsUKKQbmR3v3LHlDVzDCuXjuA9evhmXRChlP8OZL3Mx/75xD2N9y', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('08f53f50-b10e-4acd-b74b-83cfde1f1e7d', 'TFF344', 'TFF344', null, '$2a$06$agE542LI8ojLPVFYIS9IauYg6X0X3mMD/iwYP74MEIBnSI3tlAQmW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('09056d49-0fad-45d0-b2c0-335f117eebac', 'MTM444', 'MTM444', null, '$2a$06$gAgTJD8SsKa5338mFweg8e5gRDOiBubSgNMWUVQjIYvbDnKpIaGua', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('090b60e4-96f9-4068-9f78-6ed61ebe51f2', 'TAP061', 'TAP061', null, '$2a$06$hOiX1RS4020u6qPwqc3.j.H/4UcCG3Aw2eSng4fuhyB0pYCLpKnXy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0928221f-f678-406f-ac12-07e5893db196', 'TFF110', 'TFF110', null, '$2a$06$J7YiNOdoHP.1a12C1uLhpeKKzkZlqCgZGMNwKL2vzYTagk5qZGaT2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('094c480c-6474-4450-a04e-3fda35e03922', 'MTM232', 'MTM232', null, '$2a$06$VoazasnCqQ7IIB8tg2p4DOzNNgDUg.sqKX956w3RKFMHEQdbrOYze', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('09614a4a-c529-4253-b886-4d0dc0dd80c1', 'SP432', 'SP432', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('09bd9174-ac21-4796-858f-7ec46d5748f8', 'TFF111', 'TFF111', null, '$2a$06$UAnJoPYyGeEVexqqvm8OheCpJNUOFIqzY/8XkWIoFV/.IOhETkv7G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('09e77342-08cb-4b30-a808-da945f430119', 'TFF070', 'TFF070', null, '$2a$06$V8TvJ0B.u6DSx5ENyID4Xu1ro3yrP1lsaFYOWZI1/ncgEq4GUEPAW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0a09fcc5-1f3b-4208-aadb-429857892abd', 'SP493', 'SP493', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0a0b1a49-7187-4057-b9d5-5e3b36e0d355', 'SP500', 'SP500', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0ab66bec-6037-49c2-b118-946dd2a70e52', 'TAP345', 'TAP345', null, '$2a$06$HpEQA58NnOdkAlLVANOymeRwAKIPCMMHMwdBiJiaYUH1txijIenT.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0ac10436-95e3-45d4-91d7-7be592dfa06c', 'T032', 'T032', null, '$2a$06$2rsMsdbhEk/Y6Met/7zq4uB5W84dNuWvq6iNjYFzL3xLg0UNaJqMa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0ac5b16e-ebba-4164-9259-57475148714b', 'MTM322', 'MTM322', null, '$2a$06$v8ynirqGcE2qBMOBiaJIveTY1/iTUX23x1kfnDzriRrmMuCQhyX6K', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0ad0ae42-c887-40a2-9b5a-7adf7b1c8ef3', 'SP101', 'SP101', null, '$2a$06$hrhx/lV2H3lgT0NvH.hoQOvlOXu2F0BojxvGDb2MYP.xwBHXIG9ja', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0ad5e2ec-0daf-4ce0-9924-fdd04c3faf8a', 'T213', 'T213', null, '$2a$06$U9gVGJhzxrHu54hD5ZYWnex9oT4f5PZGbFj82tkagt4oaS.uTFANu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0af8c3c9-7bf7-477a-b790-1608ded98af9', 'T020', 'T020', null, '$2a$06$QaW7990sH0daIFqZzB.exuBN3fUEorBj0Y/B8y8Y1t/qRIMjs7mum', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0b2142d0-a160-4151-b621-8ba5016d280b', 'T004', 'T004', null, '$2a$06$OZH8MIgzxthYzFXFb9Y6HeRbZ6WlkcD4q6Rzpo8S0tgpd/kKvydyq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0b2c2b28-478b-4f35-8fcb-acf0c5773d3c', 'MTM178', 'MTM178', null, '$2a$06$8VRn9hLnZN0G86CTIwd2qOJaMGwsr1cGYHDpZ1tfBc46l6C03s1H6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0b3fb30e-f07d-447d-b811-0cb0b689892f', 'T071', 'T071', null, '$2a$06$K2Yf1p0juh0XP9S.5PjyV.Pa8B6FlQiW1woduoBwM3BtpbhyZEppq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0b604393-ad09-4402-a760-7b65f43b15ec', 'TFF417', 'TFF417', null, '$2a$06$R.UTkoVaqO9sakMf4i42wuQ2KtjP.4yax4sWsDvqapgCFwEk.GFFy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0b8a5f81-1aa0-4a29-a1c9-208749e2bfe2', 'SP444', 'SP444', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('0baa7cd4-772d-485b-bb2c-c920d7183a37', 'T204', 'T204', null, '$2a$06$JmStMDBZNGgkHdyHx7yAueZ/y/XYyQ6q12WnwUD4DLr1My8uo6GGa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0bc0857a-8a39-4e5f-ad92-908285df5901', 'TAP113', 'TAP113', null, '$2a$06$dOqShtAzxK8jLAe4lDWKaee79WsBFfEdpaRkgMkGQxtCHJWFfRz5S', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0bccbca3-d85a-47b4-b326-7930f9b17683', 'MTM327', 'MTM327', null, '$2a$06$l.sB1IH2EOuDu4RHMOGnqe/F65r.rHlZ8D6cvmtzhqsSdki029z9q', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0bd257e1-4047-4922-830d-eefdc77ef79e', 'TAP115', 'TAP115', null, '$2a$06$8aDDX2vukhsU.Umea7FJAuf9q6kLSwcxT/3uuYZgtj9BSWsB6VZx6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0bd7650b-1a45-4f4e-939d-6911d87ce90f', 'TFF083', 'TFF083', null, '$2a$06$f7NSxbS5qSi4HCgMoUStE.uJGKp8jdEchnPugFD2u1p8FavNTPgWm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0be3dd58-5fe1-436b-a4eb-cd870f6aca2e', 'TFF020', 'TFF020', null, '$2a$06$m9qdStzKWKvZTKQdP5m31evWgvlCTC8p0TBbqWOy.iXTHhPnimG8G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c006730-f196-46e4-92ee-ea26362baa1c', 'TFF120', 'TFF120', null, '$2a$06$C3oGLawcZzQ9f0u8ZMGt4uFiYJDG/3jQ4V8/UHen/Poi4vyefCVtS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c061d17-ae77-41e2-aec3-aea00a71a02c', 'T289', 'T289', null, '$2a$06$VDLp9LWk19.MHmX8Q6xTx.tlA7hmeCUQSOuecS1nCdgSqgvLOpu2e', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c1123ed-2a8b-4c83-89be-75c87f88953a', 'TFF175', 'TFF175', null, '$2a$06$atQ5owJE9U5H/0m5/W6DEO6tkqm2WTPxPbtWsvDq3Vn.1agqFUjAa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c3ee10f-380b-43d0-8e9c-2553123a7714', 'TAP311', 'TAP311', null, '$2a$06$HPDef5/46bVAUbAZwGurEOMDhZOli5JgceXwcK2piAdQb/BUe86wK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c47895a-e56a-4a04-99e5-e953ffc31281', 'TAP164', 'TAP164', 'https://search.google.com/local/writereview?placeid=ChIJfXzZAAAJqDsR2LbKYzjbF2k', '$2a$06$NJ04OcBsgA9xQ78oxnhBPeuJEEULRiSJdHXjIOeRxy8s36MOjsCrW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:12:07.853799+00'),
  ('0c5876b2-518b-475d-9fbe-5941aca971bc', 'TFF414', 'TFF414', null, '$2a$06$komXmROjYKUPkTMpR8U7.uJM0pII6jddT4oUCuO3c07JtjlUbMZmy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0c82a5f6-f5f6-4fcb-8538-6645d381f92b', 'T061', 'T061', null, '$2a$06$fjq9BgKTjqtZgdCAaTrCeeO4LJa51Ge5iM3L39mRw/r1g4k2pWl7q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0cc93f93-e98a-4158-8867-c1919ff08222', 'TFF386', 'TFF386', null, '$2a$06$DVMiKOAQGoCBpO8HIk6Hc.T8XaWRLkfyc6nmogwfwHTEUZU6Iz96i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0cec5625-1ebf-4258-a8c5-7bf2d16b49a5', 'TFF200', 'TFF200', null, '$2a$06$bzTKIpLfcXwVbv.ue73Hf.nOI444AMGoblGXWl0FO06XlAxIhIYJq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0cfcdd63-e989-41ed-b3c8-1a6ce833a13e', 'MTM417', 'MTM417', null, '$2a$06$XMFMq2lvIKz6srTlHLWAPunOp9OMkXTw5i1RfmSaWrQVDFcbRtVFW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d0a5300-5791-457f-9089-a5f524176a54', 'MTM361', 'MTM361', null, '$2a$06$JDgDscFhB8kRgPBuGHwzGuEeJIJDMbtCSGWj17WC7z9Hf/.psE/qG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d306300-a402-4449-9583-6a69c8ac1c26', 'MTM358', 'MTM358', null, '$2a$06$qtgleruQzuxfyym7ozBTi.SbPVcpAv/vtTGfaqpsLfnzVkjxpyyBO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d3e1c7e-976d-4388-950a-852c209b00ac', 'TFF180', 'TFF180', null, '$2a$06$7hYEgpuWTGzwpqjXRnKvXuAnGvQORb7qNKeDaeuo5O6j.WAPa2/li', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d573392-1e37-46d5-b245-0beb9ee7665e', 'T046', 'T046', null, '$2a$06$gRA93CZuWDQddL23bO72K.G4mvKNCkEjUabPqqNeTKeW9o546Q4D.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d770960-44ff-4ec3-bc92-ebd740e58813', 'TAP370', 'TAP370', null, '$2a$06$VdV.0NcRuu4ByzX6J45bj.gWv5uzqMrK0CixTLVVpsqgKPI.zNeh.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0d8add5d-0450-4021-b6b4-cb49df2ae16a', 'TAP079', 'TAP079', null, '$2a$06$8OUO07CtapudkuG3a9d4QuCJBlFmdG4sV1uXHTopGs2sfrR6LU1IK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0dcce186-3496-4b45-aba4-95d41de5701a', 'TFF168', 'TFF168', null, '$2a$06$yVjNDBcL1v3LdaYUq.z4KO50Z8QsywIOp1msVfIjeRwNsFs8F6o1K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0df64e96-0484-4f5c-a840-b8570c9788f8', 'T059', 'T059', null, '$2a$06$XQAsMKp2AF5OE0V1GiNnD.7gdN9eXME9C.yY75pVg9szUAJFYdrS.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e083550-a2e0-4f94-9ac7-b3b1dafcc7b2', 'T208', 'T208', null, '$2a$06$0wuqqAlB7SEj/tUrGzqQiOCAwK1o0AkNFPk/2owFoOTKhFBjuIinu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e18a2c1-e1a1-4eff-b435-1a390505d815', 'SP282', 'SP282', null, '$2a$06$K5TCRLoAV5PNaC.kcmRMU./CuLHI/cNfZLKTqIwRQDWcLwf8P5Maa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e19c122-e381-4422-ab2d-860710a8f6a3', 'T024', 'T024', null, '$2a$06$wpeRXBqNOq7PXHAGJfGKZef9C9G9BtiGTDWe9pBSoRSLyLrPFSIdq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e1b1e0b-d0dd-4c37-85bd-34fa53b038d7', 'SP252', 'SP252', null, '$2a$06$juJOzzai4iP5/DkbowZgvO5u0FTJYcOP8R4XOjZMdGlCcKU5z20y2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e3d9c9c-7de0-47da-8389-27156df3505e', 'SP184', 'SP184', null, '$2a$06$Mar11DUR3nsRPMIpxOxMA.rkXbFsi4bQHkUGidJl0X/dt5qXrzp0G', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e3e1afb-58e6-41b6-a444-547877d63418', 'TAP072', 'TAP072', null, '$2a$06$ZRcqvgI69eWS1Thm1pB6OueBVunL5xYK01UALjOmiX1HbNkGoKpxu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e7d490b-3899-46ea-b99a-bd2a0ed63765', 'MTM161', 'MTM161', null, '$2a$06$CO8GD4IR8U0P9wSVS6eBjei3KdoL9BWO5VnY5F.tUgG8ZfGLBjdMW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0e889a9e-e2df-4963-91a6-472e83827b32', 'TN15', 'TN15', null, '$2a$06$GbDLuKVBBj2.J2z/kd5J7.TR.69rSbyFi/ZAl8Rch4mYXeu2vRGfy', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0eaba3b0-f525-4a46-a91a-c4788fca3b4e', 'TFF284', 'TFF284', null, '$2a$06$g8tdlWz6Gi9ALntZFqm4ge6Sysea12nqBbAU1KG/UZ8KOgGlZReQm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0eb845a1-a4a0-4e15-a9f0-44e4678ca915', 'MTM179', 'MTM179', null, '$2a$06$06TmLztKxMMLFNcZn5k3/OMkIYqefBuMRvn4vlyWq6aMtvAadjop.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0ee9c012-0564-4da5-9116-7ec6e8866553', 'T278', 'T278', null, '$2a$06$Yp4h362C6aWefSW/Du5D3eaRyKp0Z7XD1C14/bs2aMijvcrsWmFi.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0f0944fe-211e-4b26-8ea1-118405bd56ac', 'T268', 'T268', null, '$2a$06$yRb6htVo7Bg0cvlbjU0P0OE/M0PxAhP/LUQ/BpEWUnumkX5wWU3Re', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0f2df5e2-8080-4015-8489-6b3129fad395', 'TAP208', 'TAP208', null, '$2a$06$AOi4BZuGj/syKaHwW/x0zu0Oqfcej6asV7qLnRgb74n59yS5WmV3S', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0f5b3406-88f8-4d31-9353-31fed0f40846', 'SP066', 'SP066', null, '$2a$06$1T4brS0oJb0Y8.Rb3rSQPOba3ZC3poKfXLDvc.rQGwXskKwjezkXq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0f82defa-3ceb-45da-8746-ed6abeae13a3', 'TAP213', 'TAP213', null, '$2a$06$7IbuCI3XTf3IlDclQnWWqeMsOw0i/iK8O4VZ9rGT/yH9c/khX8ZRe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('0fa6cfc0-7748-4fec-a2cc-418461870d47', 'SP390', 'SP390', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('10052349-2b6f-4ca0-ab22-995da3974b87', 'SP308', 'SP308', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('104d3250-1e92-4d28-80f7-a7bb726355f4', 'MTM275', 'MTM275', null, '$2a$06$OIO05Qu8FWAujA2DI3rMUeGMi5EwYEatDKE41c6LYoG7foF23m8TO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('10545e4e-7ada-4fe1-aa65-7183f1e9a560', 'SP248', 'SP248', null, '$2a$06$kN.Ft9YQSvzm7lt/n0fzDuY2eCuVtikpNlig5mE0XLiI8W0hiK8Ke', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('107ee683-a66b-4955-95ab-3f9269ae5f4f', 'MTM365', 'MTM365', null, '$2a$06$hkG8uyEWhrHMKGbqZIJcfu5FW7CvDk8cH8J1LKvu3CRkq4KFzR.7G', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('10c65625-1bfd-4b0a-a88b-cf73f523a228', 'TFF234', 'TFF234', null, '$2a$06$8R9FetD0kiy6UI6nQRTztecF0UfCgSBQgtJb1zi/Zhp5QhOjpRJo6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('10cc012a-6c16-4a81-b471-82c825b1049c', 'TAP014', 'TAP014', null, '$2a$06$9aj0JFH1/6u8EHt.EC/7auMUu/eJ.ucJQ5OLXf906JrvjU5muKglu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('10f071d6-47eb-471f-8776-cdc084462f0b', 'TAP068', 'TAP068', null, '$2a$06$uEE6nhc5Pu21w9gmTXYMduPmVmFzFjKRJoG7E.lvyWG.6mRygKvaS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('111af50b-fe4f-442c-967e-3cb909b1951c', 'T251', 'T251', null, '$2a$06$lle9R9IhEZmto3xx8thMwOZDm5zl0y/A0Ups2d6B4v7/Dr2O40Voq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('111f4e86-a42c-45e6-b832-ed09b2826cca', 'SP228', 'SP228', null, '$2a$06$9yoFKXC47zRns3RLeAW4Au8AfiPl1psxkVaQaaJzVVS9mPdzKI0UO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('11465b56-3efa-4ed4-8b85-2cb0cd1f103d', 'TAP131', 'TAP131', null, '$2a$06$Gsdz0jxwZkwaDQWJqbsCN.SW7JberOtv/wdhRr0BDa4GSSxU7ui1a', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('11742eaf-6bb1-49af-88d9-7e81dc80afbe', 'TAP104', 'TAP104', null, '$2a$06$r0BmLQbCDxeVocIy7tS6L.d5GGEvJ9VrY2pqj2b0uKcay7Zw9vlbu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('118177ed-faaf-47e7-a851-e37f0e125214', 'T144', 'T144', null, '$2a$06$87EGcxgVbhhlWMVr1H/7PONZ2z.r9QoxsVA9dSdph4NgjllvvvvDm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('11a04196-fa10-4e8f-8a82-700b3fbb8934', 'TFF341', 'TFF341', null, '$2a$06$JNjF5AMttXtIo/DhoIDETeADedAhi4PKbCy.JRU3WLYZXHi0OGiRS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('11a32c3a-9162-4ea4-ba66-9247afabdf93', 'MTM152', 'MTM152', null, '$2a$06$SFmITAsE.spz7zThcneEeOnvSPyz/F6EfFxcPfYOkQcQl.gh2xqpO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('11f4a065-9c71-4ead-9019-b4b158b319c1', 'TAP248', 'TAP248', null, '$2a$06$JSEMkrdnvS9Wdfc2G7tBcOX.CmAZbUZOgRdQWjngHmLg/vj3CRPga', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('120749e6-35fb-4aac-bbbb-5bc2ecd45e99', 'TAP295', 'TAP295', null, '$2a$06$LH95Ep/OoJ57bbkmQ6x/7OlFuqEpePbqmbR/yLf2or3C/yrLbgSOm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('12515811-e30a-4d0a-abcd-3888227b0598', 'TFF054', 'TFF054', null, '$2a$06$v2e5vEknhAHqowDV9N93HOkuWm42t8IaALXQA4WNEkKqFKG6yd9Z.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('125d47a1-d555-4bba-9c24-f67b82860fc8', 'TFF204', 'TFF204', null, '$2a$06$Ipn9jYawqI2OA.7ZWZ7Yz.LslwPqZMz53ZlqZis9WRi6TkagyHQfa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('128824dd-6b9f-4c82-b0ab-3b9f2879d586', 'T089', 'T089', null, '$2a$06$n.3iiyaOsKTLB2HudIrxwuaNBZZfhaCgO/xLh4iZ0CytsIw2oSkj.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('12a1616e-4d39-4921-9681-1db8240af58a', 'TFF117', 'TFF117', null, '$2a$06$QffdUQAkw3d3M4GoA.MLJuXKsoAa0pRooM.0xAKXgUXZkIPsaboxC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('12ae3130-a61b-44f7-9483-201b73a8cfac', 'TFF475', 'TFF475', null, '$2a$06$PqfwCNadO24282CUDsVRBeY8hcxxpeGeaAlbZJSesodjCdpKwBFdi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('12d65642-1eb2-4008-972d-6e19c1569862', 'T227', 'T227', null, '$2a$06$nSAj74vyYNy151mf9eqLt.BOkPmmZi0ePxeglTgrKBZrxR/YM04Ia', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('130adf3e-de65-4fff-ae9b-6b68803f26f3', 'TFF428', 'TFF428', null, '$2a$06$4gz81KE83WgIos53HdwqjO3earq2UKI4qPyACz0Iv2NmqIhJBG44q', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('132db6de-c5ca-4088-aad8-18035b3b42d5', 'TAP052', 'TAP052', null, '$2a$06$FZ7T1KgW.aLflXgxcBEF/O7y6AAEXfDjzhqBS.f6iEZB0sQdANobO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('132e04a8-2f01-43b6-b819-fb5946c8d508', 'TAP250', 'TAP250', null, '$2a$06$VJtg04pWx8n5nJuWGrDCX..lDq3FvMmUYWlW6RUuoeH5icuLkWRcq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('134b8f71-dd7f-44cf-9310-ceb67df069f3', 'TFF028', 'TFF028', null, '$2a$06$r9JUBi2OlIFLysNRv9xro.Jr3MzB2MhLqCIFcskG7wQ1v.wfBcZ1u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('13877ab0-53e2-4e24-879a-f53b936e6dec', 'TFF322', 'TFF322', null, '$2a$06$kDlv9w6m9faoMRvK6ODNkOWJhsjU4yxZlDjz4UpPHolNYbyVSJD0G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('13a1f905-e673-4b33-bf09-be58ae94fc19', 'TFF212', 'TFF212', null, '$2a$06$Vce2iGmFbroRbf0GeNUSd.TPcKvLwG0GfpcETURyW5Qy7EwfoDV6u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('13f12781-f68c-42f8-8994-f56eb99e797a', 'SP387', 'SP387', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('141f93ad-33ec-4b46-aac2-31d0cc7349b6', 'SP486', 'SP486', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('1434f2c2-6c76-4f86-8f62-656075cb3639', 'SP070', 'SP070', null, '$2a$06$dFlPP8bIl2oVn57wqB9Bk.H8BmAnoDmim0J32vFT.lexz4TyjCYFq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1448ea25-75b2-4cd1-a789-515ce7e591f6', 'T215', 'T215', null, '$2a$06$SGjMEmZMk.gXRigedI5n6.KRmK4E96I6xAYuzOG1hDDdvWXk3Tlxm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1450a4d2-81ec-4caf-bf16-412f2f10ba4e', 'MTM150', 'MTM150', null, '$2a$06$Y3xhuO3LWrua6l8V9z2zqu3sTHJYIBKxnWqZjqJLbSQO4snc3Qy7e', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('14561d00-e911-47c3-af18-9e70b252bd81', 'TFF031', 'TFF031', null, '$2a$06$saeEqH2fI.oeK5fUhlBsKu.qU29L.MNB7oBlGHkp1tNT0KwFycoyq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('14738174-6cb6-45ba-b289-a1bb604192fb', 'TAP150', 'TAP150', null, '$2a$06$G14wUACuewPVxIT4dCHstOUwOoK1SqK1ourhEA39mfad45OuARnEm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('14813a2a-2205-47be-a029-8901347401ff', 'TAP234', 'TAP234', null, '$2a$06$uAVUuo2KV.605NORSuOEAe5xvgfWQgHcmo5XA4qu.eYKnpsDWAxoa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('14bb372b-075c-452b-828a-dd571b95912b', 'T266', 'T266', null, '$2a$06$0JaQo1ccT19DnWu7hUIXKOEZo8f2301HA9d6dQ5rEdK/Jl7Yrdikq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1517503e-8d22-49e4-bf44-654cae5f065d', 'TFF130', 'TFF130', null, '$2a$06$fC7jynKjsbJgDv3vJXvCpuVHwkWmtWOuF9fFiK5xfQa3RQ9ecY5iG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('15496d21-fea8-4531-812a-9aeb1be3132f', 'MTM271', 'MTM271', null, '$2a$06$a.GRVCOaUWcU8OJUFx70EuhOkr6RgQvqxgZz2D8N7g.5Mvg18hod.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1557adbe-266f-40a5-bbd3-c4171b367cb5', 'TFF310', 'TFF310', null, '$2a$06$6Jvzl7xtWe7ambvA.6T.YuisM73sKrz7EAdwh2ibmcX97uvTr3//2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('158f8dcf-9161-43f2-98ea-4556fd407181', 'T143', 'T143', null, '$2a$06$faAv4gfQ2G8kviP94ZNVs.fEbxvlCBDnYZhE1gKBrwFt7yDXIRH/6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('159e377c-09dd-434e-9f0a-0c6c9707b416', 'MTM265', 'MTM265', null, '$2a$06$9EdiiAxs0cilXO/ezoAk3..4QO7/fsSuUuQQP49K/zEUMBaZemDT6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('15c8312b-c33a-4376-a380-9f6bfb8a2aef', 'TFF046', 'TFF046', null, '$2a$06$sBXod.AmZGnCW1DQks9k.evABJqCZoWi92XFSlKRgB.L.Lvtfgc8i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('161285bd-5c8c-40ee-84ee-eb332806ebb1', 'MTM332', 'MTM332', null, '$2a$06$YjIQ.Yk2tH8.pn7fJCKZYOEnk2a08WRBty.WePUYMdmcGmt5xcije', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('165d2581-0d75-4491-b4ae-418dfaa25f7f', 'MTM250', 'MTM250', null, '$2a$06$.VWNdVPzfG9j8itPpMBfXOjUAR8GYkvI7UrVytu/WN6Pqk34BQwju', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('16765347-df11-4651-985d-770774983e59', 'MTM172', 'MTM172', null, '$2a$06$LXzOxYtivQHmQlN3gVWArO2KMko7YyRndFIojhWedogvfKEnNXPuC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('16af1205-28d2-4725-8d62-b45883228e20', 'TAP343', 'TAP343', null, '$2a$06$8H41KDE5WMBRITPC997c5.mAjfX4OrpSOdlf9sBj4gEFmb3AwYFEy', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('16d8cc42-1f71-4687-a84e-bd5c0ed20481', 'TFF221', 'TFF221', null, '$2a$06$PMhl.VAV/xwTboe66l1AGO4fIbof0xUPsCktOLTnykdUWLLxbp45C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('16eef308-bf93-4dcd-b11e-9f127b3f4cee', 'TAP095', 'TAP095', 'https://share.google/GeEyi0z9B0MAunc30', '$2a$06$meIPAhNSKsYSM3Atgynyb.xUCRsZqiXWJTzdeyhEFhc.U3fATLO1a', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:27:24.769623+00'),
  ('172b184c-30a4-462d-9dbd-48d7903e506b', 'T282', 'T282', null, '$2a$06$PJ94N7P8eHnuppfN6r/pk.N3XdkjQllfZiVq5MxB5kB.q7AWahW4C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('175337c9-917e-4c7b-942b-eb2c2c6a9256', 'MTM199', 'MTM199', null, '$2a$06$m48lF5m38R3DmNVlRgfIVeSQlyAFyYT9q65AJxBVK5GMAc.2KApIm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('179e4cd5-68e3-4e06-b81e-9ff2f202263f', 'T101', 'T101', null, '$2a$06$50zMXYYZwPSXJFgNmrlaIusSjey9Jtydva4tu80ATc/ZaUY8EN596', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('17c35123-75c2-43e9-a286-572c0f1d7a24', 'TAP342', 'TAP342', null, '$2a$06$uDhrZUjmeqwZjsx05afgmuzz3u0W7Z9UfaDCbXN3lhwelPLKjLz6m', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('17d2bf38-b897-40cd-a093-90d7aaabc7c7', 'SP051', 'SP051', null, '$2a$06$Nkjn.W5dm9TkOiUFklMrCuS8VhXZwCj1eLTMqgdxQh4X7s/LuR7Xa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18244624-3bb2-433a-aa1b-28de1a20105d', 'TFF419', 'TFF419', null, '$2a$06$rL6jKYaZ.AKzik8E6l9jk.vWPwpKYXbutVHHu5zXKGA61nJ/I.ttu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18279201-27c3-4b4a-8701-504df48aa128', 'SP261', 'SP261', null, '$2a$06$g0z.G7TMWFwH2UU01v56GeQmCYsb6potTyMK0rYk/GKDx6QZRityO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18361240-6f92-49e5-a43b-f3463e4ae1fa', 'T272', 'T272', null, '$2a$06$U6J75mMIwx3LRGRw89d/ouCesSk51AZkrTqu/l0dTD9byEvnYelru', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1849f1cc-e451-4d9b-9b89-8b49da711f1f', 'TFF463', 'TFF463', null, '$2a$06$CjYbc3DOLDo1VbczWFpqeer3tXZV4JdK8SSjsg4gViQJflb/XYrRS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('186343d8-d44a-43a2-9a7a-50cc408a7cd7', 'MTM405', 'MTM405', null, '$2a$06$5JxjCr9/WL.y.urvjpzG/eHGCX9sGuDfwZuMiJrx9gfgGYhDp1i9i', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('186667a1-4cb3-42bf-bfd2-94c6d80520be', 'TAP365', 'TAP365', null, '$2a$06$7kM.7nXYGWQdM5Ak47h96OeYid0RnsUib6YyszohEEaEt8AP9OlGq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1884cde6-848f-4ced-8c88-17bd82df8349', 'T220', 'T220', null, '$2a$06$KKQ3Ss/..DAvI/HPlb.NF.TC1u/dNzH4rSbHn3.KERaFTOEo2CGVq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18cd62d6-0f8e-4f04-9ef5-8f27090516fb', 'SP276', 'SP276', null, '$2a$06$O2joFAkMpd706xPJhgJtDeHHsOvPs3SUzFOVDNJZcxdGnXkoeqyj.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('18d12a48-e24f-45a0-945f-1604d79f4da8', 'MTM196', 'MTM196', null, '$2a$06$FZoY.sVhhb6NHftBxZxF8.OCgsCFS/eY0C2pNhYVeuKGntWH5OSbe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18d4b470-49c3-4612-85b3-ad3757ce07ad', 'TFF152', 'TFF152', null, '$2a$06$2YrEvirGDJB3NWn3ez36POfS35ywYyrHgTKk/77c7yp7XdZqnDEk2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18eec5cd-0a31-493b-9a36-590ba50ddb01', 'MTM127', 'MTM127', null, '$2a$06$S3onI5Qn0xg.dvj6U/3ze.sqfyMmVcRIpWPvDmqqwRbW6k7kLqiXi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18f019b1-8d10-46f7-a5a6-46eb7f3a6f93', 'SP061', 'SP061', null, '$2a$06$MOPqoO.a9DOsFQk4v25mpOuhNJLsuilrpgJg3iCxhLphdLYXbaEzW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('18f906e4-afd4-4788-ad92-6a8ea2025557', 'MTM122', 'MTM122', null, '$2a$06$7TYBE9G.I5K4vYtZUix3MOnNyMSI5GFKbhqS8MCrOdyR9qPKPS0Zu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('191b3805-b373-497e-bec3-edd262fa30ee', 'TFF198', 'TFF198', null, '$2a$06$FnFdEofctgAe1p3aItMBwuB0W4b3gE5hiRcWgO5yheEXcbbyd7Jte', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('193afd9a-271c-4eb9-9911-1d20d7bf389d', 'MTM134', 'MTM134', null, '$2a$06$ZVHBxKMi0xcx/uFou92UN.v6KhSc86GF78szfrwXRoYV0SBe/Q4Ki', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('19488259-89d4-41ad-8d62-541858f67e5d', 'TAP141', 'TAP141', null, '$2a$06$vFtu36H6X5gLHVUdgn6MV.fAbdApo/H9piUP.OYpJ2bKrW1uHbqx2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('194ab6c0-c6ca-4bfb-9f5f-5b8f84248ea6', 'MTM335', 'MTM335', null, '$2a$06$ey3di5jTSUmQUXvdRj3MkeoTg7xBKcsfsLZRDC7EDtk2/TgpVaV0u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('19b24bfd-d738-4289-ab98-678e250bb19f', 'SP225', 'SP225', null, '$2a$06$/.l2TA88EwFfKwpJTPsQUufD3vJvjbZ1dSLIJC9HeMR1OJ360iSte', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('19cfc44f-af19-4daf-a650-1afd4e55e3b8', 'MTM145', 'MTM145', null, '$2a$06$dbQKVT6Jfn/xy0kPXtyo2ePxmeNM0q/cblGfrMFGgoRIN39WPQUhC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('19dd3423-53a4-4eec-be0c-7d37886a3f16', 'T263', 'T263', null, '$2a$06$YIoUZ8qswd5uEDZ/M48yqubLSWiZzQrb51whzkrN9hZ78hJBOHgYO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('19ec3fa3-a4c4-4c6a-9f44-016488a37c4d', 'TFF265', 'TFF265', null, '$2a$06$FleEI0.jgi.03m10/FJA..c4nig6eFBs0MawhxgAuwTaRBULTWRmC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1a0db00b-6418-401f-b078-75f9e7e1436a', 'MTM445', 'MTM445', null, '$2a$06$u0ZQMCv5HZ5vBEsL33nY1OvsDOV5yZ078c1v/RmCdneEOeKlsDbV2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1a127a0f-d737-4faa-a985-bc5150c09ef4', 'TFF243', 'TFF243', null, '$2a$06$5UrGq9l5vZr.r5wUbTSzye8XMzta2ZX83Q6N6XcNQT/QDzzfudFPG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1aa99b26-8a0b-441f-af88-5636e72444f4', 'TAP257', 'TAP257', null, '$2a$06$jacMhoReRmKxY8GUQI9sEuw4.zySrZDMUzlADiviE0XkXlyIxSLtK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ac24857-27e4-4880-9158-af432a1c8220', 'SP142', 'SP142', null, '$2a$06$muoeY5yTaIPkAKzdtS5yje5/QiFewxv1NskFKYUDi9Y9.3dU0fFXm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1aeda110-2bfb-4348-9257-65bc79abb01f', 'TAP363', 'TAP363', null, '$2a$06$aHIQVe0SNv7Id8Mwzz3VfOuXvaUenXXSEsC26DJe2sEJsiYmmjXA2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1b0a92d0-9b43-48bb-a2a7-7f7fcc8c753c', 'SP130', 'SP130', null, '$2a$06$bTeNt.ujUx1vQSc1wTOCguWgN3CxKs4zYffzz0SlCM9QLBmZxmGxa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1b3cc745-55c4-43d9-b80a-5e8d4a95c059', 'SP009', 'SP009', null, '$2a$06$BZu7xsTFpgiLYYdqJ4FkbeQQWyHInYUVm8frDrBKRCllbDah4Ih06', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1b576be8-35a5-41d9-bac2-8aa8da8dcab8', 'MTM326', 'MTM326', null, '$2a$06$Md1TDiuIr8VbyntcaYWdX.fRkg8f29xjTvMQeHDfz9FcT/vCfbHim', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1b7233eb-f4e1-4907-a0e3-5064f20246b8', 'TFF146', 'TFF146', null, '$2a$06$4ath9HZP9IRIYX9qIEc.7uUqDbMdTvTn0.WMWOIzcEYQR9CyMnwmm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1b97f8ca-e809-4009-b89b-eb6cfc92d917', 'TFF248', 'TFF248', null, '$2a$06$B.Ynwj04jUpB28JR8.Me/Od0CbVXhCrOIm5HDH0IJwDTRk8pOmgnO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ba5b92a-39e7-4f13-8155-5addee91f5e5', 'T096', 'T096', null, '$2a$06$CcOHH9rdsWgTJaeG8GL2p.OXbqGRl0dyCAb7L6PSKlY5mEv5Bn5im', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1bcf0d61-8ee4-4ade-b9fa-115e8143395a', 'TAP388', 'TAP388', null, '$2a$06$..xnDe8GCdtGZ12jVzgqOeNvcqFgJRm0XUiistlUaNQXXyVVSKGja', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1c165fd1-30d8-4a28-889d-b5e355757428', 'TFF470', 'TFF470', null, '$2a$06$6PYcbriCnmNorg9TShSgOuXi0aajWyiXLmZfpY/5MqRjlYs.3UMhy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1c4998c5-f202-42fe-a1d5-018bd23eb5f1', 'TFF041', 'TFF041', null, '$2a$06$/r9BquPpSz26sMeojNXMeOon0sReetJJ9rh9Bxx1N/AqZl4V9chYK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1c857863-2141-406e-a747-d9dea7a71b58', 'TAP114', 'TAP114', null, '$2a$06$6vZJ7UU4vP7E9dti6cT8F.5I0a9VbDzBg3TLznIBPOYRUM4xNO8fW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1c8cd39c-17d9-4c70-8d5b-6645c20a7742', 'SP079', 'SP079', null, '$2a$06$q4uQB34MnakTwfQOSfNZDu0pmliq48uMHHhHyF296YPUc7.FEzgoO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1c9af9fe-24bd-40b4-ad09-a5ed86ab800c', 'TFF235', 'TFF235', null, '$2a$06$ZbCiCamDlXUyInGycfbSrezcb..oYLLC3.BeJxNsIugKGfqhuGKLi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ca6b824-bf62-457b-a39c-ba8381e19d39', 'MTM424', 'MTM424', null, '$2a$06$IeQwMOT5ymoqiw46FX.fO.FbkHfVZ6NMsQMfypVhwKzGclpS9yGWK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ca9024d-f6e7-4564-bb40-d1247163d47b', 'TFF259', 'TFF259', null, '$2a$06$LCrL5TBlbTAtr15HQffwVufscCmgKO/1sNH2jX/EPWA2PDWsIxx16', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1cbdab59-32a0-4f95-9bf3-88794684767a', 'TFF448', 'TFF448', null, '$2a$06$ySaLsrJCxoDk/6Iu3IVwx.s64H8corXs/IqMlGkLBmLEjip8yiH3u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1cdc97cd-1e7f-4889-8aab-d1c839f1168c', 'TAP186', 'TAP186', 'https://search.google.com/local/writereview?placeid=ChIJXRxmYmjrDzkRwsaI4PPWluc', '$2a$06$YjDZSnkMzcw1MZY/h9ouB.u3hkdeBuF573ayvXbxrN4rHjqDr0MJ6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:27:21.855062+00'),
  ('1cecb821-710b-4b75-8195-5ce35c7b04c1', 'TFF143', 'TFF143', null, '$2a$06$DfI0mBGkUx2sXG9yG8fke./QVAWWi9tlam.ri6btqe.J0mMx.qOu.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1cff5c15-bb10-474c-97f2-c945896e73b0', 'TAP066', 'TAP066', null, '$2a$06$1X7aiAJ3Q1Z4FfiPzhsw0u0blgFIL.d92UccdIMXNQDktLC0ayUC6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d083cf5-2f62-484d-a1aa-fc1c9c713a49', 'T222', 'T222', null, '$2a$06$36CAWn0JvTRkwvXmxBHQ9ezCY8fmWYcMF3aWi/XWLG43Q8FP5QqNG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d12629d-6023-4562-a8d8-7ab8110b5617', 'TAP167', 'TAP167', null, '$2a$06$nlEb843LkMw4TCagttHdtOgPWc3PgHwluXyuPuEgl8nHI//C5DK6W', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d1820e8-d64b-4292-a226-03738d7d154c', 'SP197', 'SP197', null, '$2a$06$q7FzmoG.fDbK7WDvUeOFwug4jRXytXKz2XNARUrCaWST//uY.PRJC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d30b82a-5e3d-4162-8b33-9d9e8a38df9a', 'SP371', 'SP371', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('1d754c88-be13-47ba-9738-f21b0cbc86fc', 'TFF217', 'TFF217', null, '$2a$06$wvQm2aiKFc/RYB48troEi.kACW6UlLYIKEDsGeSBCNChwZvFIYlaS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d8e9894-7ea3-4e08-a8f5-88e61643a433', 'TFF354', 'TFF354', null, '$2a$06$Ekr6k9dRmyCFO5vy2QJGCuxCPzDV99lM72e/xEEzNfm8E7/iDbocu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1d911b58-7da2-4acf-a156-49fcdf04c199', 'TAP207', 'TAP207', 'https://search.google.com/local/writereview?placeid=ChIJdXZ-zR7rDzkR3zAv4gAXxLI', '$2a$06$1tY7nSpVPumGstQhAnbR6O2MJdHT1R7Ah28V6/rSMaPXWEMbIGSbS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:12:22.687799+00'),
  ('1d9e9654-a721-4acb-a880-4ada3672cd3e', 'MTM263', 'MTM263', null, '$2a$06$o95qvbsTl.Fd5G8sd9sSg.IqHjLxITgNawl2L0FhVZ4GKMawl.pIq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1dbbe9d7-718f-4974-9683-ece486f144d7', 'SP152', 'SP152', null, '$2a$06$aeZYtBgbKMtaEhk90cvC7OQsZJkdE2efXqji7IKKpCiwSsKHMWLzK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e1a819a-a085-4dad-bc32-a1ec437ae3cf', 'MTM244', 'MTM244', null, '$2a$06$0ilnE189R8oRt3UsD51wYO11ptDlbd9egRznP8aFlt34dhHf3Ye1e', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e210be2-c496-445a-b39b-8c40eae31beb', 'TAP130', 'TAP130', null, '$2a$06$IS50uESX.6SBlzv1irIh4eGA.4jpu3xF0Q/OdIsKWMZDjwnbJqqWy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e2c185e-7eae-4304-9acf-ac90ebfcf692', 'TFF038', 'TFF038', null, '$2a$06$eGMy8wE9DkvVVAifPPDtLeyCcz79fyCEKQZYsxihIUOlQxsdla5XW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e2db9a3-fd70-4f91-adef-46213076c151', 'T151', 'T151', null, '$2a$06$/5LdMF17eXhtoBQE/KCzE.X5lTeHfSzI82KIY4rFYO6X5niRhltAy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e35666c-3ebb-42f0-a14d-0f18887203b7', 'TFF055', 'TFF055', null, '$2a$06$zRe8maLDxXhzGFnc5axXNe0PPxyny.L4XdNahDl6s2WBHTL2ONNUy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e3a18e8-dce4-4d32-aae7-3e7429ec5fdc', 'T077', 'T077', null, '$2a$06$nwBu3ZfD6gEZPBVKneBHbOZdGCgNKpmje.zp1Urm9fGNgC/AoTwMW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1e415b42-506f-4989-81cf-22775e4d32af', 'TAP156', 'TAP156', 'https://search.google.com/local/writereview?placeid=ChIJXRxmYmjrDzkRwsaI4PPWluc', '$2a$06$Bt8CWr3TcxMPUBIBUSAxUeBIUzqD0fXmfKDMujKp1/OGw8oVcLnd2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:31:43.538188+00'),
  ('1e738aef-bf39-46f9-b0f2-3898fd36882e', 'MTM334', 'MTM334', null, '$2a$06$Z7wLBB36ie4foLJYJ6bgkOkJgGqN8uiYZqZen3RN1VPf3gavBdVaq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ed4e2a2-b2f3-4349-9ffb-f1e7f3dcd007', 'TAP029', 'TAP029', null, '$2a$06$qZrElpG7f3fL037b6Swd5./AR341jBY.xcN1gbPlDn/bGnmn3vq4G', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1f1b7901-2658-42e2-b0d0-d2443f550d11', 'SP284', 'SP284', null, '$2a$06$IXFVPMgquGEsELYXHxqXCe7BkkF6RjBn.sCmBS3oMZB5fkZSU3e1a', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1f21fd58-c4bd-4cf9-b676-9ec644806d15', 'TFF472', 'TFF472', null, '$2a$06$g5CsCmB0R7Nd3LTgf8D5hu0T4UIyqc/Eomwoe5zafqPkh4EHKVLXC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1f4d8d03-9ca8-4fce-8a2a-a9afdd8f7c78', 'TFF022', 'TFF022', null, '$2a$06$Kj0oP9l748a8KcwOzlP0hOffnGjdabpwnkdgf.n9c/Rwe0cS/7qeC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1f70417e-91ed-4398-a171-4450f7f1aeda', 'TAP337', 'TAP337', null, '$2a$06$jWQZpDikIsS5RBydY2/6i.3AHNsKyNnjp5Z9rvjQlLyWwhddzalam', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1f769caa-af72-4d13-a67d-0c850b08b931', 'TAP059', 'TAP059', null, '$2a$06$QEu3.4FxwuS5jnMjpFpf3uX976FZMznpbkKMbKQdDwEcnzcQxuY6q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1fcd3146-f0a8-4b68-be4b-8e96d3543609', 'MTM246', 'MTM246', null, '$2a$06$kIa/PULwy2xFtuO6yP9nA.y/Im1PWAWTJEzV/5otuiRW8hYSOUNSG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1fe5c069-9aca-4afc-ad52-a060d69a0ba6', 'T028', 'T028', null, '$2a$06$aPm/6n2.b6Kj.7cfSbK7m.ukySfKOam6VEMbsSswHxCRonmO6lMPK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('1ff3afd1-fc0d-4f28-9c3f-045f4865b161', 'TFF023', 'TFF023', null, '$2a$06$ftY.wPjhalmSW9FQuQ3BcOTUP1nQCUwlDur1sHClzB4zGkMHkZ32q', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2006bc90-1353-4842-b4b7-f742a1937de5', 'SP289', 'SP289', null, '$2a$06$HD2jTXvk5WshFPuHgAQ9C.JXCNvdm9fpFv7Z7HlIaxnxBzooSWphy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('200ef0b9-0090-4222-aaed-f17d4b9a806a', 'TAP324', 'TAP324', null, '$2a$06$J5TY00/verbAPIp6sN9d.O9mIUvQkg1PiGVMDcLMuOVMf3duohpg6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('204bcba8-9c3f-4785-a48d-4d5f2df8e479', 'SP431', 'SP431', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('20909fd8-46bd-4742-b4d8-a4694844268f', 'TAP296', 'TAP296', null, '$2a$06$6WqSXKqGSFdFBm5OlbGjy.gWHOAzKd0ANU3dfs2Ftg/TIlYK1WV4S', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('20d5264a-650c-4537-8aac-3b3a8bbfea5a', 'T014', 'T014', null, '$2a$06$Tln06pxHfK30HKivZM/5DeHDI.9eN9Vp/IN1tYhE9fxhJz3CP2Tfm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('20ded006-abba-4716-bb6f-993b1a7c6cca', 'TFF257', 'TFF257', null, '$2a$06$tNyn.ZVjXNJAcz5o/sgeoOLC.cI8e2TVANmboimQe8s5ZAWgz6R8G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('20fc00eb-537a-42f1-8982-a255114b986b', 'SP395', 'SP395', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2142d0e0-d42f-4134-b7cd-5825474bcc29', 'MTM344', 'MTM344', null, '$2a$06$XPWujmA9VlPgkajI6z3vXuOuTilE.0S84qZPtrqpJbv9Dm0Zb2Ljm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('215bffab-6aff-41c3-b7dd-3781b72d4720', 'TFF179', 'TFF179', null, '$2a$06$o5GzhL9CYkRFwfHSDuVYU.Y.VHFnKxsQULvEdVsKLbOcMOpWsR4Qa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2161eed3-8b16-45be-b6e5-f1d349f6b4ed', 'TAP008', 'TAP008', null, '$2a$06$vg1FFxGNL8w06SCcALXFUevI7ZVAVnxl/hJV7CC5MY5EHJjKuccn6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('216432b2-5051-4d13-8ee3-341330883882', 'TAP021', 'TAP021', null, '$2a$06$CnxgFdrB.dVmQ/qSNT98cewV2eT9GuN6H/QlxWxWz2/uNWa5Hlbqa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('217cd32d-909b-4060-91b3-d88561f00b39', 'TF03', 'TF03', null, '$2a$06$sUIV75qaWHEjBvQJwin6rOwT192SjVdyUEGZO49JQ9awc00ZTsAjO', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('21c3907f-ad75-4767-8b39-a41645ae3087', 'MTM140', 'MTM140', null, '$2a$06$JdGT6reu9Nh6csPOxjp.juHiRkQs5XjmcV7.7G4l9yHjnQSnQ46Gu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('21fe70d1-903d-4ec3-be19-702dbdbe3f8d', 'TFF073', 'TFF073', null, '$2a$06$vo32cqjNNcEQTN.oyN4/OeXpMVqgH/tUaz4MiiMcxDYuu/4AZaToy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2243f47f-43c8-430c-9951-65f90c493858', 'TAP152', 'TAP152', 'https://search.google.com/local/writereview?placeid=ChIJF6scx3uVDzkRwN7nvkaSPSg', '$2a$06$6.0muA9TVHdrV9FR29iLGOmhXaZzL9s/UgnlL9C6zYkTnwr2w0L2i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:05:39.569745+00'),
  ('2246df4d-ee49-459b-9e26-41e64f0f16cb', 'TAP291', 'TAP291', null, '$2a$06$1Rf9fO12KxpirornWHxwv.KDXbiTVZW0TeDsTxzV0ODoUa1I7tX3W', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('225c8bb1-3692-4aab-a6bc-88e0a0bdd4aa', 'SP401', 'SP401', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2269f336-682d-4ad4-8022-adaa88cc1875', 'TAP017', 'TAP017', null, '$2a$06$EFCDzEoPw4b..hU9oon/fe1mMpQRko3ISbzBpNn/16l7JIFe4.rDS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('22796489-847c-4792-b7d9-84dcedbc6b62', 'TAP171', 'TAP171', 'https://search.google.com/local/writereview?placeid=ChIJCQpN5TXrDzkRRk2RbkCyivA', '$2a$06$iQMA6u1Nd9/Ts8ApLCUNM.rjZjJBE3UPvI76S/Cs8xX9rcjzJIfC6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:45:03.258691+00'),
  ('22b1013f-a634-47a2-a9ed-ce46214b60c7', 'MTM240', 'MTM240', null, '$2a$06$yLYvrCy5FjczmpKEuClTyOlQR0zgcbuV8otx03rL7UYaS0SyFNkra', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('22e3efa9-25a4-482e-914e-ad886d66342a', 'SP011', 'SP011', null, '$2a$06$uH3bsUW0pGcgzyOfVC8n6ufLluSZEcBJtu1XdDIjMT12IdL2jWnNK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('22e502b1-79c8-4d91-90d6-ebb52ce015ba', 'TFF174', 'TFF174', null, '$2a$06$aarU5GPcVVaiMO3s1S9zKOXFO6sF95IMUcAZ5cXftUzPTpsvVYLaW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('23241493-d65b-4a8e-8c4d-cfc89438ae22', 'MTM260', 'MTM260', null, '$2a$06$3lKCY/BHXUGNlEiesMzfn.V/g6Hzcd0DzaO4GG0CUHfa.u6idp.vu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('236820b4-a78b-436e-8787-e66679f3ae84', 'SP103', 'SP103', 'https://search.google.com/local/writereview?placeid=ChIJ5Q0vZf6_DzkR_Q1WaENkLds', '$2a$06$MrV0Kc0nVF15LMXEcjCyL.P4Oj.1X827Vf5UhrNNo.CESJ5f5V/v6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:41:43.843491+00'),
  ('23713791-16c1-47f8-b44c-d65b43c46d57', 'MTM261', 'MTM261', null, '$2a$06$P547MQWHZqh7wCqdmaJZG.gms7.YCPP7L9IKDZ9/snQamu46JBGNK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('23840ab8-713a-4e0b-ac04-ebd7e259e74b', 'SP022', 'SP022', null, '$2a$06$YO67skG5h2sKPaHy2/O7fOOmhMRUXQkj5N2ILOOhX2lqSBN6iJw7W', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('239587ea-ab0b-489f-9a37-99941baa3167', 'TFF499', 'TFF499', null, '$2a$06$MpoWzee8/.5ehmVL3aZxhuPlky8A6n9du72NXyRn0t.NysE68jWRW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('23d19c64-c1f3-4a7e-a9f3-efa13ee366d9', 'TF01', 'TF01', null, '$2a$06$qN1nIqkJsaBOeDfhqWn/bu1ahY7RlW.XLbrjfxV9o0FFAq6nikwfm', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('23ef6e95-9b03-4786-922b-5e071f895a1e', 'MTM173', 'MTM173', null, '$2a$06$RI6qdlI1FFpqRJLm2oGD3uYEAd/bmHehmum14AxGlZMYOU6wzrNT6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('23f16cdf-94a8-4644-88e7-69f6e81851c5', 'TAP188', 'TAP188', 'https://search.google.com/local/writereview?placeid=ChIJx6F_XwAJGjkR7Pg4AHFnglc', '$2a$06$6MYlAbI/lxlohDb2xkTFvuBxLB/HlBFSrcIZLKuRro6F10C3QPbB.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 09:31:44.537711+00'),
  ('23fb4618-a0e0-4e34-9286-912f92cb668d', 'TFF403', 'TFF403', null, '$2a$06$6pmlTqwH9x/B585HiVyr6OXKT0Se.c1bZtM/nXW/eVCRrMlvBCHPO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('24029bcf-8313-4d67-aa96-38de0171aed4', 'TFF207', 'TFF207', null, '$2a$06$p8Fbtrwy88.kt3rpV96STegch6aXaxkJGNnSYu/XXor9PYBJI8n7S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('24497af0-cf14-432d-a942-f3a5c978df5d', 'SP345', 'SP345', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2461d4ed-90c5-46c7-aa8f-9c532f73a05e', 'TAP185', 'TAP185', 'https://search.google.com/local/writereview?placeid=ChIJ4eK7vSjrDzkR3wVdl4Yy4Yg', '$2a$06$Gwky/wT1elD5EYZWp6qG1.rE4l0I.ZWU5PRXCfVor/8pvMZqe8M4.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:43:57.205221+00'),
  ('24625102-fc54-4520-bacc-afe4067b29e8', 'MTM190', 'MTM190', null, '$2a$06$CNW2/Hl5tZz7bcNydKJ7vOAnuistb2giobYT29mgBK5hssCPBYfXi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2476942d-ee5c-4f09-b81b-28f13bb0781e', 'TFF247', 'TFF247', null, '$2a$06$b9bI03lkhA9gkJkMLAKt1OIitiQDSgIWciY6GqhHI1Zuval9QTOd6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('248a165f-aeab-41a8-81e6-65d92cfa6210', 'MTM224', 'MTM224', null, '$2a$06$BrcPhVDiQXQjkID0mh4uR.RotUmCTOkTVwxycLnX.5cvr6vuqQqcC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('24f75efe-97cf-4b25-b9a5-645daf27bfb0', 'TFF052', 'TFF052', null, '$2a$06$JQaBWHw7PAwjg2AtJz8VIuvSwpnxEMOhhJcPks5Ax/BJ02pjzag5W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2542d7fb-ad9a-4ba8-8bcf-ff6bfb20f2f3', 'TFF268', 'TFF268', null, '$2a$06$Abg9eslG2eGZnRUP5mLoTecc/ipS.TWwnQqvbZnkurCrIf.yw6YUW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2549c1b2-d8d5-4faf-b173-eaa7a83a93a4', 'T192', 'T192', null, '$2a$06$kS/EqE/aMDN96R1EfYi.iOnhB63FZjyACA1mGgT0VgkPixACPYhQm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25871c1f-2fa5-4db7-b56a-b52ca151a9bc', 'TFF399', 'TFF399', null, '$2a$06$rhgypLDpmXklQWvhpNnsJ.SXhoxt8x2cva4Ki9qZ4O9bpFOeXDYYm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25aa4427-1af6-4d99-98b1-6c5b9bd8ebac', 'TAP358', 'TAP358', null, '$2a$06$08o49HXjkny8uc/4gOM9Ie8s6Y2byQlFWoh2jpG9SPqhkioznX1ae', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25bbe880-eb67-4c92-a546-d4529941e23c', 'SP019', 'SP019', null, '$2a$06$RRWknXyaNLvJuSr0A1xeGuTbHgE0q.LibjWtDKBjaB6NzWKBPVvLy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25d0bcd4-0c74-495d-a41d-07945340f0f5', 'TAP098', 'TAP098', null, '$2a$06$f8LeIju5rON3SZHI.gUNwuLs8Y3kQIxuuaGs0ahJMdiMo3yTyzDxe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25f511ee-4936-4af9-869d-77006ffd88cd', 'T100', 'T100', null, '$2a$06$GMmp/x8BcNUHl.A5GNo/fOMQFKDd5spOWsnEH0VkjUDd9luf5q3la', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('25fcd2ed-cabb-4484-a3d5-184b22de6663', 'SP453', 'SP453', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('25fee237-977e-41e9-a8c0-6b3a48e3e8b1', 'TFF358', 'TFF358', null, '$2a$06$XvBcLFTq4SJjmJmGsrt6t.XlP/0rLpbLXIRPMTHPMxXLtHP2ExemO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('260841d3-642c-4c84-aa89-253ef6884663', 'TAP236', 'TAP236', null, '$2a$06$gC19O1XXurywI/pRUfnkGOt.fJLS424rCMjhJyyYVeNxzffkxlmZW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26394cfd-daa0-4494-888f-2787d45a8a81', 'TAP181', 'TAP181', 'https://search.google.com/local/writereview?placeid=ChIJc5VcgqfrDzkRFpelQ3cstgw', '$2a$06$EQcsMS8wMrpZ4Mjo1uqGk.14HzdWgm356Ymg4r.8B/RV5IR0qKtIa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:05:38.78184+00'),
  ('263a14e5-e090-4655-8122-005f012b9fe0', 'TFF278', 'TFF278', null, '$2a$06$wYV7x4iwyHBbvvjrVldjDu4qd6MVCIBRO8gCuKKryOHTrHSQL.gv2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('264d1086-140f-46f8-aa51-a74317a5412b', 'SP442', 'SP442', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('26573d0e-443a-4386-bbb3-89c97d8a59a1', 'MTM289', 'MTM289', null, '$2a$06$P7i8VYld1rHiPx2dmkTCvezDd5QhnRCZe2Q11YOmxq5d4h2OaSE7i', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('268f0ff5-58ce-4ec9-b153-881b496f2ce7', 'SP365', 'SP365', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('26ae3380-5c85-4c8a-8f62-5b81cef05e7e', 'SP242', 'SP242', null, '$2a$06$UOlo.MaNAsnns9dRLBWLeObSbR6n6gDG5sX69Tb.06BwG.OtirXKy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26c23922-9456-4356-ab03-a39b26fc6450', 'TAP379', 'TAP379', null, '$2a$06$Jrl671efNPqUZNtg7WqIFOcULZK5D0Z1xPmRRMdy3lc6vzcgys1SO', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:24:18.255266+00'),
  ('26c73214-fef5-4316-800c-9942d1194943', 'MTM410', 'MTM410', null, '$2a$06$CJZcu43RcH0c/WR0cT3JvupaA0yuWgicFEcm3dBl0NVio/RpO52Nq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26cd744d-8149-4595-9a6e-60d03808aae8', 'SP053', 'SP053', null, '$2a$06$Tez7F7TSeHkeMHTz.LlfpO8CN9b1gt5EvLz2ene.4X2T0FRg8xg8C', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26d33a2c-014d-49ce-a815-243101413cc5', 'TAP111', 'TAP111', null, '$2a$06$/W0fmrFJToBTz8xVWfE3quOMYU.DJ208ZGAOt4pJvaQ9q2Fq78RAq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26f66952-97b2-41ee-a47a-7965f8274ddc', 'SP290', 'SP290', null, '$2a$06$j.IWnItp3lONRztmm6iQhO17RPDn7OlE/vIMmn/0O1Pir6FaT3wHm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('26fe62c8-1cfb-41d1-bcd7-00ccb881229f', 'MTM243', 'MTM243', null, '$2a$06$yOfIFQIMgQghfsJlc1qgHOh.FDGzySPyxkjcye/wGxx2ot70/HG02', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('270a9512-0e24-43ed-8598-fa86da850af8', 'TFF301', 'TFF301', null, '$2a$06$LCuZsLdyvQLim8drnDpRMO/o1bLL74qEuCDtRMw73h3aw7qYD..6C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2723713f-0ca0-49a6-b579-dae7b0c36609', 'SP472', 'SP472', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('27634a6b-d9c7-4ec7-8067-0e405dfea4c1', 'TAP292', 'TAP292', null, '$2a$06$uB5Je/6Wh/z3jHRKFmRrG.56xxxwXpXclAPlfxhxTpo3.kJ5xLHb2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('278ac8d4-5f23-4ccd-a280-9b59cfe0b8af', 'TAP288', 'TAP288', null, '$2a$06$dmLPha/Mx6Zjv/sM5MkBou0IwYqecvCbPOvIYNu8CONlIFqS7eW16', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('279a6746-2e87-481e-ac2c-e85b6cbba5fc', 'T159', 'T159', null, '$2a$06$8htZArOW9jUkIyiCBHAFW.VAgAZPabvv89WJFmpQVCB9b8uVMXr9m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('27ae81b7-a83f-4f7f-833e-8356d9b8414e', 'SP408', 'SP408', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('27f40bc5-1ba7-41a8-8f83-1ce034bf822d', 'MTM163', 'MTM163', null, '$2a$06$8QLnKFU/afdAiPABeEVuHeTSa1hj0Rzzv58DcOUWBbeLW4Tmt1a9m', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('27f95f7f-d8f6-4eb1-a5df-cbbd16e5d0b2', 'T068', 'T068', null, '$2a$06$jQMt.joAGNHs/5ev13blUuHIZDNs0De8Os/KLqiwBDEYwP.c25KnS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2813ba9e-da22-45c1-ac36-17dbc15258b2', 'TAP047', 'TAP047', null, '$2a$06$peRMCR/0mLg0/C/3AKNr3uG/BCNnpRE2r4adp5YY5ymQsFYFpy9A6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('289b69a9-cbce-4d04-9b8d-8a6a95fa14d0', 'MTM331', 'MTM331', null, '$2a$06$GEVx.GtbVRxZiQ6Js.f.3el8xR8J8bSGn2UTlXq3bYYX7sgOLzgvC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('28aaa4f3-67f8-4841-82e6-0c57c2a3f9c0', 'TAP191', 'TAP191', null, '$2a$06$kXqvNQRsTGHQ1Bkl9sLu4edIdktI6MLk8lodNY4HWz7DU48h1d24.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('28c5c332-c1aa-4ae0-9164-a589c4cd0497', 'T175', 'T175', null, '$2a$06$7MXPz4ZfQMVQLI1O/7rVC.Y2UnrlW1FWase3tKnutY5EL4sEkwWBS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('28ca7f90-c27f-4299-b7ae-3e63d97a3917', 'MTM380', 'MTM380', null, '$2a$06$SwBwICu7gjaiTk427nRNpOF7yQ/0DCxSSnb6RrJfPcKYa//p858k.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('28d782e5-4ad1-4b6c-b748-052f931462e7', 'TAP237', 'TAP237', null, '$2a$06$udEi/WPloTGmTMbx/zSjfOs6OBvlGolJkQJZ9f0NDbwatD7w9tWNy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('28ebd3e3-9590-4690-94e8-7817ada59608', 'TFF430', 'TFF430', null, '$2a$06$.8rYOFUOVfHOQ.uIUgJeYOyKtd2S28Qf.xY3binxZdQX4c5flYTqa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('29246245-4562-4ec1-8e74-61eae534b363', 'SP441', 'SP441', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('293f3155-709d-4673-942b-7e216b2e10c1', 'TAP030', 'TAP030', null, '$2a$06$s7CGjSmcT3wGtMzo9Q1fyu1H89qufaVlJBY39RCdPUN2vYujnvsT.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('296fdbd4-c13e-4b29-b632-c96c8d0e42a1', 'TAP297', 'TAP297', null, '$2a$06$eC40L2KrpN1g3c.nfLZn0e3wlDgqgzmZwSa5M5NJFIWdCh8fq/UTW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('29712985-ae80-4481-8387-c43a2ceb4212', 'SP226', 'SP226', null, '$2a$06$V6IkRJmffFK8RdyHrpiwdOGWTJ.o6TPxqUoTL/b2Qz8t//zMS2zVG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('297fad51-8783-41f1-9140-186daaac5a56', 'TFF263', 'TFF263', null, '$2a$06$h/.IK/P2O7DRHQiVAyiWoOND1HHPcHBke4EYU3w0hndfaL14Hob7G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('298a0424-cad6-46e0-a19a-be7594c313b7', 'SP466', 'SP466', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2995f37d-f2d0-4ff7-ac46-2f93cc00ca77', 'MTM320', 'MTM320', null, '$2a$06$n4tzw0eKI1C3MhHtvKSCCuSaQmypisRbEPeLuvQMGs6nfPKjFRIJO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('29b2e6f9-7687-4eb1-937b-1e4fad753973', 'TFF027', 'TFF027', null, '$2a$06$Jv1Wz.V9Q8y0nG8ez6EcwOS1BBT6fpnGPrcCliWTtQDIgHvTVkw56', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2a04fa11-cfe1-4c03-b48c-393fbbf6c24a', 'TN20', 'TN20', null, '$2a$06$l3C56frkhGTBmIVkeT3oEu3D0I6ybplxUJBy8.zmRZMUYwddZVkxK', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2a330c83-00c7-4f73-8485-85f2a842d096', 'SP468', 'SP468', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2a65a99f-53fb-431d-aed4-b2ccde0cef85', 'TAP249', 'TAP249', null, '$2a$06$19W7vGJZCKlIhFAxzJ49Ue1ZybdFwBM0IwDFw5iAEmCfeDTCPtlIG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2a8f2679-b540-4b35-92f1-dc5facd4bdb3', 'T202', 'T202', null, '$2a$06$KMCOPanyNekusGVA4DseyuoUYyuXvPngglSwaVNZcV/c61hVEJUde', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2a9f4f9e-4396-4d97-9336-687d0da53dda', 'T017', 'T017', null, '$2a$06$qzeK5qSbAEb5E2iTKwXjAuI4Ob7jlk7kbv5UjpFxcbE7svy2u75yi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2aada9f1-b72b-4c69-9b76-7e8f3a670f8f', 'TFF034', 'TFF034', null, '$2a$06$TftN9gXxsV7q5N6/fhZny.VAlG1pJhJdHqVYlOLpqMfCICyrhX55m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2aadf506-6d24-4c78-9fd7-9923044fe7a8', 'SP210', 'SP210', null, '$2a$06$40gOBVgbL4PqBdfCYLEi/e8eru1YfOO/GPkOCLdwyIb/meOL78Kb2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ad0eb11-549a-4701-bc69-e3ae5d3b55ce', 'SP362', 'SP362', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2ad7f73e-5be3-4d13-bffb-75eefd1ec7b7', 'T179', 'T179', null, '$2a$06$7ZwmyHkvnrZmvqErPF/1aOV0D4r7mPNvt7Srew6NLbBoLKW83ZZBO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2b2b7ac8-92e4-45b7-ade6-f86f18a7942b', 'SP155', 'SP155', null, '$2a$06$PSTO2l7rMBAyJO7zCh9Ir.cz1ysOulovB9bYOitV.hJK7iSYO34nC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2b44b82c-f27d-42e2-bc66-7b48c5e99890', 'TAP266', 'TAP266', null, '$2a$06$BANKc0Jj.SKbLnJiDhbRQu4Ycca6TLpGN84bMO6aaqld.TVc4/nS2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2b68e864-64ec-47c6-b4f3-38e230301cec', 'TFF490', 'TFF490', null, '$2a$06$HZ01dXtNB1wytvQNYpjk7u6rnzesGiKZcEoYiuKg2aMSYHjWAu/0m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2b820c67-750f-4a2b-8e25-d6449d04609f', 'TFF456', 'TFF456', null, '$2a$06$24ViZJDvbcAhAeTRTIj3gOAs7Wfe0bOH//QppWXXu5L/.1tENbaaG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2b8e4e4c-f60f-473f-9384-9a0b0641a60d', 'TAP081', 'TAP081', null, '$2a$06$D5WCtgHJakKgKSD164Aqr.yM3o0gaz9w3z4nmwsbaOneMY90WKbZq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2bb1933c-b84d-43eb-b705-7d759b29108d', 'TAP028', 'TAP028', null, '$2a$06$gfVX7tafZ/wd6qcRNq0/8.OtRGrYTMCKO0w4kwvbEn78KFM/J/yWm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c129976-ae57-424b-98f1-7fb09c6b1bfc', 'T132', 'T132', null, '$2a$06$H49YmUVE4t/5ZvZTL9S7OOZfcRubO7OremAih9tXx9Bs.Mra7Xp..', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c3557af-2df9-446f-8766-04604acae653', 'MTM267', 'MTM267', null, '$2a$06$8y1W8rGPN/ZWj7uTnm1EKe6XdQZBiBy9CdHZa10LdkopuoSEoKCC.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c35eff0-d113-4c55-8011-d06652d05893', 'TFF045', 'TFF045', null, '$2a$06$IP0iDkXB4ekTEzZdlzkpjusS9ZsyMpgqkqVvDZqtobp277X48c1se', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c364895-914b-48ac-a62f-9be42088a2c4', 'TAP282', 'TAP282', null, '$2a$06$QoUgFgGR11M63ariegiJm.JNWvCKhKrtHiU5UPQOON5IoXNUfbMpG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c52d2a0-6db5-49ac-86d0-2af829a0e849', 'T223', 'T223', null, '$2a$06$E.9UDdnIlq/lvqBeW/NjOOEvw5IQqsyEJlLqVxs0AFGXw7O4ha8sO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2c8b0a32-8c22-41a6-8ee9-b80996ce4579', 'SP459', 'SP459', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('2c8eb20f-0507-4c07-a2fd-34a95df9bb01', 'TFF086', 'TFF086', null, '$2a$06$RCyADw6ea/ei5NoHK1seCuxhLWIUeiUYgPbNEhA1.onCuN9b4x3Y.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ca287e6-b959-4da6-b643-51cf864fa907', 'TAP323', 'TAP323', null, '$2a$06$Ki18FdPdumP6cLyDFkb4quYAb3PeTENyCQQjyZZY.0.pe6YuXo2Bu', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2cc640a6-f087-4277-9a6a-1911dcadb8c6', 'TAP069', 'TAP069', null, '$2a$06$bvysCnSds/QvKQ88Av6FmOuduBoqMLPtpBXcSx3LATGvZ1Ga2EzAy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d0a08f2-ba6d-4d65-9b62-6a24f1d5c4f4', 'TFF061', 'TFF061', null, '$2a$06$SWVIbVs2sqlffnxlHOOT8OpVgT6Bgq.P7E6M24tJAoJrr3MyhN8gG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d4ec233-0480-4611-817f-c0f3e2bf9a20', 'SP291', 'SP291', null, '$2a$06$m2GFZvzNEmQRipPeaK.e9uL28B7kLbEb0O6WWV/DvHM99I9QuNY.q', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d55d74d-1319-4096-83f6-9391c37180d9', 'TAP137', 'TAP137', 'https://search.google.com/local/writereview?placeid=ChIJ-VLgOX7qwjsRaNvY2gFbHOc', '$2a$06$vbibqrB.9jL2VQSml58yaeGN1v3cre7W87V3qnlsCqstE53AjmiHi', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 08:51:46.996707+00'),
  ('2d60c246-f28c-48f9-9265-b82593a76b03', 'TAP211', 'TAP211', null, '$2a$06$CiuXHnOXmM6lhNEglLyH6ulqg8aLrLKkG/.W5IzxbOeS4dVZsI7HW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d7f121e-9f3f-4f13-8260-7c3cb5fa5695', 'TFF342', 'TFF342', null, '$2a$06$VSJUaBrEocVdby1..L9G6O.lPBmoJO5SEYHcRjq8OtXtej74Bl12y', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d8d4654-8c83-4e61-92df-3810587bfcae', 'TAP396', 'TAP396', null, '$2a$06$2J2Lgesf5BbKoyqu5z2Md.UcW6Zvnm3c1/wx7DTfAWpaNjJtJk/vO', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2d9fab6e-713e-484f-894b-f7d32d1dc5dc', 'TFF050', 'TFF050', null, '$2a$06$cLgpXHjlsBKOJFcCrtDkOezOEFdJWJ3RM.wBMEzPlI3jOMj7DJWfa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2daffa4d-0b64-4a55-826f-17dd81f4cae3', 'TFF142', 'TFF142', null, '$2a$06$dj/A64sYNDjtVapnu8PzY.o9ul3GxXWqASTROzcgEXlUGAfS0w3Hy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2dd873aa-b3f0-4bef-9157-aa70359f5dd2', 'TFF216', 'TFF216', null, '$2a$06$3lVDUUKKrJNX3CEOe.u0jeuTqtpuy9sOZGNGulscF3nJHGZHjrlvG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2e2ebc32-39f7-41df-8d6c-f45457aad715', 'SP088', 'SP088', null, '$2a$06$VquFhHIK50tK38bJHMG0XuIb1cnJD6aTDIi3nV4Rds0L/BIPPstDO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2e474edc-5335-436d-82db-607cbf410444', 'TAP036', 'TAP036', 'https://search.google.com/local/writereview?placeid=ChIJJePdCHLrwjsR6NDkVTOnQYQ', '$2a$06$pgpu9rIESMw4TSUfrvpR6OUdg2ua9kjaL5unewjb7wSVDOYjjbVSW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 05:32:29.129163+00'),
  ('2e74ee78-65d1-45be-a430-4d7b63931518', 'SP161', 'SP161', null, '$2a$06$tv/JRH/5G3Hf2XhF5QosreYV5KUNKbcaXGmcFLHWIVZL//8vtAJkK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2e8e0c99-aed0-4f24-86d4-923ea469c912', 'SP259', 'SP259', null, '$2a$06$QTvh662okB1sW/flklN44OQV/pB9YLxRuzYR67gogaDPPlfXjj/y.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ea29123-0dc3-4930-bcaa-9ec4f572b5f0', 'T015', 'T015', null, '$2a$06$YuvrCa4wPcKmIpB7vAprLe15Jc.W1iBlTu4X2vo2u69Bj1TUqX/AC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2eb2dac3-e996-4e92-b178-9cf3c69e48c6', 'T016', 'T016', null, '$2a$06$FnomRM9iHX5IOQBcb.ShZeqZ9Gx8NuR5nliorLE9kbqF7iah2f7/2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ebced85-036e-4cb8-8c14-9c9eec0f221c', 'MTM136', 'MTM136', null, '$2a$06$fUEXKZ4nx9twKphSG4muruKZW.OLKeS9TLhLjr2G9aLgUgXVrrMA2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ebfb67f-33e6-4348-a20d-db7bec223058', 'SP287', 'SP287', null, '$2a$06$SkeVOypzdLS76HHe48uSuOWPKz/jqDPWNMxXNKlqFWF9QijZH4.KK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2ec8456a-18c9-4734-8667-0bb93928a5d0', 'TAP219', 'TAP219', 'https://search.google.com/local/writereview?placeid=ChIJ67XTPSbrDzkRC9TGwo8_Lss', '$2a$06$naEYARseMffmO16Hv5/8Buf15A7ekOgJQJ//d0KhP6j9kL4QRY1xG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:54:47.050569+00'),
  ('2f546bd2-ddcf-4d40-bcbd-ee83cc270f81', 'TFF230', 'TFF230', null, '$2a$06$LCto24Za2MfXDR33Ced1HuMXdgrQuFCqKDh2HH6kFl/TY.Z5GNotG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2f620b54-8c71-49c1-aeda-2c35ece53352', 'TFF334', 'TFF334', null, '$2a$06$J9YRuQ/XpdIFU/Y3Lnxmiuc16Wh0.gobsFmSi/DPSZvXcyrLQMr3C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2f6f9e96-2754-468f-a6b8-e417a0d3dd19', 'TAP326', 'TAP326', null, '$2a$06$Mg9yey2HSk1I2e0hKSOwJuJPTC8m7.6wAivOiQKVvi4CF19W/j12S', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2f8d255b-cf35-4543-a228-fd32d9442bed', 'T242', 'T242', null, '$2a$06$H6SyAhNAA5zG0VpH/YHhlehmnJNw5jAI1DafcmAsQQcN5URzPu09q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2faf2d28-08ed-4dff-bc4e-ae798e57ffc1', 'TFF170', 'TFF170', null, '$2a$06$EjDRQC4.0FGfj2Sa.93qa.XGI8Y.pKWqwH407WlFaZxKjwKWw5jAW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('2fe0fc3b-0dc5-4370-9a19-10df662f829b', 'TAP313', 'TAP313', null, '$2a$06$vCbs3t8Z4segQnuLzm4jHu34iCwEdlbnU15hceanT5.jw74gYc.S.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('302624ae-fdd5-45c2-985c-79b57798becd', 'T274', 'T274', null, '$2a$06$YCHrdFtfDjBNE7dxqqLBYO4xIJIee1trS9zLbNBqnoYh3TFaspm9i', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('30272bd2-ac56-47bc-b424-45f6bddb721a', 'TAP206', 'TAP206', 'https://search.google.com/local/writereview?placeid=ChIJLUxA6EnrDzkRCRvGsCL00Rg', '$2a$06$P9ORqE2nHFvGtwyZpFQeXuQeRP/bxhb5vwh3dCUYYzAkr7NRW0kvS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:09:14.741802+00'),
  ('309bf20e-bd98-4521-b877-a4b96f8aa42b', 'TFF407', 'TFF407', null, '$2a$06$eTPNhhcKhza70GY.0MQBnOHbNZs5oHYLCxNdtPYOKYp4ct1b6BtWK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('309caced-5bba-4597-9cc4-ebe31e93df28', 'MTM226', 'MTM226', null, '$2a$06$A0HA6SEDd7HiJMNhSrTBJuxysMHph6.LlgzFVPhhGSirRoJ13i4Gu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('31489f1f-9b21-4c0a-8033-28819a90c034', 'TFF360', 'TFF360', null, '$2a$06$qq5bn8qvYUKwVI55WmiRjOJuRxjask7d5YPIrV/kThly.2z3PLrsW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('314e7d29-45fc-4c77-8c4f-6df2177928ab', 'SP416', 'SP416', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('318c6ca7-9200-47df-88fe-d47982930835', 'T300', 'T300', null, '$2a$06$7xQVHvmyMUXtf5JXxtzIc..ImHcY0yPPs6qEmcSndOBDqC5xCjqdG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('318c7c57-6caf-42df-8bb1-ee384fe95ce1', 'TFF042', 'TFF042', null, '$2a$06$Y1AXZYzDRa71VnXLMS5kIOx.VPScTkagfN2JIhQr2xPLUSQOwJmPO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('31a61d29-752a-46a9-9ceb-e4a5fad0acac', 'TAP135', 'TAP135', null, '$2a$06$mdXVZohyXcz2MPXAj/K4juxyHtTx0GeoIZU52m9OUpkv4VjWZVjUW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('31b73e0e-06d1-44eb-aae2-ef7999765b29', 'TFF318', 'TFF318', null, '$2a$06$bOiSFgfqf4hAERleS/Sdoulg1OM3jvmftqWptSvpR25HzKRPQEnJG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('31d94754-b1f3-4487-989b-cdbd22bda6c2', 'TAP320', 'TAP320', null, '$2a$06$4zxxk1a4wbq6Rc5Z5zefUO3YtJ6Q1aMpxCh2EuEX3p6PB9HTbzy.e', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:23:10.684008+00'),
  ('32039d92-6f7d-4b68-8f00-415b55231a42', 'MTM422', 'MTM422', null, '$2a$06$mSEoWnLe9PqwgLun3aDIGuEQ7OJMO9ldBweV14657lOE5pegY7/yS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('322744d2-a18f-491d-a9d3-556070abf343', 'TFF166', 'TFF166', null, '$2a$06$8HJJPvpzcYWLJXqfAOlg4.2lkhifJZyc/rYjKWnYsHvlPr88Yd20S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('327d9020-af09-4ceb-b91c-d1f4a4c8c817', 'TAP084', 'TAP084', null, '$2a$06$gFDJLL1sd6KKOsAHfufDYOHPHGd5nALTfFTPXgFT3FU7Kbf81ViOO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3284c9c5-3dd8-43ae-a70c-6d5345605885', 'TAP116', 'TAP116', null, '$2a$06$k8njDI/5cWJz90ZqX2vEZOk7OSuWQLlWpj5pSX4ZvcuzxTHfXiWBu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3293fffe-196b-4392-bea3-02f617be63f9', 'SP413', 'SP413', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('32985c13-ff7c-455b-bb93-18ccda291c2e', 'TAP024', 'TAP024', null, '$2a$06$nrzm4hGNnTNJ0XI64bb8..27DjbGdiM7mV1cmaHEmqR5GAUTN6wQu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('329f05c8-9ea3-4e29-8d41-9d15eba8bd6e', 'MTM421', 'MTM421', null, '$2a$06$9JSLv/g4dvZnOPt6EbGO0ef9NnjHS5THb2A4SoXMvhRUOOzEXU/U.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('32a9098e-62f1-4cc8-9f86-acf684ba0ef4', 'T216', 'T216', null, '$2a$06$iQMt3VM/2eveymuOiwXsTeSz3CxdG9jiMCeZ0q/i8tXRRXqSJ.Zk6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('336f80e7-8054-4958-884d-e136c98c70d4', 'SP098', 'SP098', null, '$2a$06$P327IoMGHxbJQgbuFiWGieQFOEDUT4/t8iCe.1ql4VWTu9Oul/3Jq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3373e44b-21ed-40ff-97bb-83fe25aa60af', 'T271', 'T271', null, '$2a$06$YnZN9wMUV1ENhi//6pNQqukllmQBixo.0Cf26Iq/Eskiamu4qhxxC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('337de349-9e11-4915-b522-2577924a1259', 'TAP350', 'TAP350', null, '$2a$06$xE8PWVrU8UEXWJSVwP8cGuSee29rag7NsCug71phur5pv5HWgtL/G', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('337feed9-b142-47ca-8ae6-aef3745e4e37', 'MTM370', 'MTM370', null, '$2a$06$80OGIiyu2ZdZIZxkBtN6pemkLxYoar5D7O8JrU87TEyuPBLBPxSxq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('338475d1-2e38-4c81-9cd3-2ea6788e02cf', 'TAP204', 'TAP204', null, '$2a$06$1oH4ZkKgET6mrB2KVRFhve1chW3mEPS4JvWOkhisDlVc/GyX9tiim', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('33c90eab-8d97-4082-bf47-0221032f6944', 'SP265', 'SP265', null, '$2a$06$poE6/Ud1CtOueUZkyeqkEu216sH1ufoiZBSoLrfPA6tcs2JkH4DDS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('33e18a06-971c-420c-8247-2c179b0b2598', 'TFF353', 'TFF353', null, '$2a$06$kzPYBpxkBzFEpKfxX1.YIucO9G9K7IQKt9WCHYERNqjJjBoXjhXIu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('33fae15d-1cae-4c16-8477-32af4fc801ce', 'SP256', 'SP256', null, '$2a$06$wtFep7E5Yw6PS0Q0yfx3teiqNS8cwSem8kbSNh9ftFlIm.BlCWLJK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('34092698-9487-4c42-ac38-0df6a5c537ef', 'TAP258', 'TAP258', null, '$2a$06$76rxdFiDDRSQq49BQVU5Nez5ry5DBCyIj.R6F87kk4HjYDIe6CubK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3416c846-7314-4bda-aa12-31c8e564272f', 'T060', 'T060', null, '$2a$06$AFiYMrUiiOE.xCngy1ku/.DvxcMi0PELqAw.ciSxaDGQZKTnVqmci', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('342801f8-1318-4a25-9486-658ee5aea4e0', 'SP286', 'SP286', null, '$2a$06$PodRbpicHFs9vi7kCx6N5uVjvm6/XymkY0t.JOFU6Uglvw3pjOXum', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('343571da-70f2-42fe-a0cb-eb32e8c6645d', 'TFF338', 'TFF338', null, '$2a$06$x5.caXjXJtP1TRybsISmXup92IADkYJ5DxHyn6IBOPyZZ3hwBO4Nm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('344f8a3a-0272-4854-995f-720c0639c044', 'TAP090', 'TAP090', null, '$2a$06$vWEloz1rnUx2U2Rdb3IYm.OJbjEywPLYk981hVwozfty0h5hsZ2TW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('348347e7-c7c4-45eb-a8a7-884ec40a836b', 'SP168', 'SP168', null, '$2a$06$HtpgaYQeIZN0YTseZfpc5uR/ghME9Yg9Lc5bNzTU9iIt9W48xOwQa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('34840f53-8485-4716-a67d-30f7789c6620', 'TAP373', 'TAP373', null, '$2a$06$S2ZdzqyzdOs.mKF.D7fVz.xGRcFOQWp3riyjmTdeaCwmcTBdjBwMq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('34be9b8e-780d-4302-b3a4-c35757a17fb8', 'TAP043', 'TAP043', null, '$2a$06$BTamSes4RcMxoiZGMZ039e8SgUo7nCZAcpVRyK5hKKfC3RSSqE46G', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('34db29ca-82bb-466a-81a8-7cf180b6b96e', 'SP213', 'SP213', null, '$2a$06$zuPwwRi5rGK45gtzEpMFB.550kb7beuBH84MogQWb6ObGd4LjYNiG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('34f2a309-801f-4ea2-a104-e9f316966717', 'SP114', 'SP114', null, '$2a$06$P0w6X/hNLUeIt5Mm39dqpeceGRM18MHnaqgo5fMWZIV7Ph9dqWucK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35584497-1ca6-4689-9418-7da9458f1d90', 'TFF316', 'TFF316', null, '$2a$06$r77KBtPUmIk3.VPXjtqcUuOF3YRGmoZ22E4Nf1bvIiRzFIS1WuMAa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35770ee6-92e2-4c0d-a5be-6fec26fb062e', 'SP187', 'SP187', null, '$2a$06$324On05ZjhN3cGicXTT6u.6KGOSlwqZWkLzvKr.q1sOSisrOdBkb6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35795c75-ec90-46d1-8220-bb179d338ecb', 'TAP273', 'TAP273', null, '$2a$06$9fStu2xdPEr0q4.hRGfJ2OgbIkCjOJhzVWJBsaUKXVUgQs0MP6k1C', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('358b8ed8-f327-4c8c-935c-117aa3ca76a1', 'SP448', 'SP448', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('35928696-908c-4ded-b8af-9f551c63b495', 'T130', 'T130', null, '$2a$06$c5yYHIvqNBhtB1./0xP6XO4jGhsqTQpUdVciie0bJbFENgzHNW/1i', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35a72a04-0189-44ad-b6d9-ea501da9974a', 'TFF385', 'TFF385', null, '$2a$06$KRYtMdkx.MA7OJrOHNB/0egmOxAKli1OBV.HRbbhNpbR.v80Sghs2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35ac4d43-0ff0-40ec-99c1-c78efd46b523', 'T168', 'T168', null, '$2a$06$O4tnvtlttVN0r8fCCqO0/ee5y/FhUvgTgVXPc1xAHDq13WwmflRNm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35cf1d31-48e0-4203-b4e2-e243f68ba8ed', 'TFF003', 'TFF003', null, '$2a$06$o8mus/VAYOrzv8AjjBDFj.PveX6TJsQbRo7eqMxm1C2rIcJ9r15Uy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35f1768f-23fa-491e-8134-c1061e3f6d4c', 'TAP362', 'TAP362', null, '$2a$06$boGRZKr2XlWQ8cMdO0RkhOeXe0IfoZZXZVg0qQzw0C4dkHvSxyxUq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('35f761f2-0de9-42bb-b853-f4aa6775a348', 'SP124', 'SP124', null, '$2a$06$H8OpcyezVmertgYlMvHxJ.jjdZanvLHTXHLxYG9QQ.CPb/X8Zriku', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('360cd030-00ac-4e60-84c4-005785a4456f', 'TFF329', 'TFF329', null, '$2a$06$uhcafolVj5BZAQrwVcQE2./Y7LSEYOa.hm4hxz92ucbfRtHAjSk4K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('361a97eb-6af9-4026-8c94-a93481d82456', 'T083', 'T083', null, '$2a$06$FFF1RIlM9sRhzIlbh8O/2OF1LY1twPwsYspftGcFHPS.hAi2sxSwa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('362a7cf1-adec-4a1c-9136-da4e5cea0af5', 'TAP163', 'TAP163', 'https://search.google.com/local/writereview?placeid=ChIJvVpH6f8HCDsRhTSXW9dMdrw', '$2a$06$BhJXYct2wbWcNzpasbY3MeLIhUSlQG.xeTh0XoTbsQS6KQGDJBx42', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 17:15:19.284206+00'),
  ('36a39ff7-c548-4311-8ddb-e9ea64f08898', 'T249', 'T249', null, '$2a$06$p9UsNNYA96LvFJhoP2TOPuKH24f9H22PVBLin/3qKW67zLJdSrkPS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('36bb3694-7982-41c1-bef3-a0a01e135803', 'SP258', 'SP258', null, '$2a$06$UVh6L0dilFG9lodxWphHremzBl4y0wecs/zfGwxququckoUdnClLS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('36e17619-74bf-42fa-93e5-4ac1fa658b60', 'TFF307', 'TFF307', null, '$2a$06$NVVRjPwoYfBkEvJIiOlUQOQdgIvGaFpWnwnMeVOA6WPgI0zQOxnle', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('36ee8b41-973c-4605-9d80-fd0a14f5eea7', 'TFF082', 'TFF082', null, '$2a$06$E9V336QsvWFzjXXoD86QBOoAtIwunaKK6oMkxOkqEne5KO9NJTJZu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('370cd6d8-24a4-481a-9c6d-668497afbc0d', 'TFF482', 'TFF482', null, '$2a$06$m6YWRoSrrxVk5sTjkIfDHOyG7Kh2vU02rcTfveFO96rzzAn6b7tCe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('371d190e-0500-448c-b14e-e4877e968b17', 'SP046', 'SP046', null, '$2a$06$mQwTySXzmSxjqPLdA.RjDekDR1FWVd.r4WjsF66g1mXWkdp.NG6.y', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('374abfee-3784-442c-8277-a4ce1b98fa21', 'TAP022', 'TAP022', null, '$2a$06$3ofCOtAW.LiEFu9JUj3BjeVNIhjs0rlVKApIXikdx2bLyR2mmKp.q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3756418c-8fff-4e28-b831-5425ae3d75dd', 'TAP285', 'TAP285', null, '$2a$06$Q/FI.2jC3XHL9yBhKJomvePcedzN6YO5lsVzVlYusaF.zkyPtKNPG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('376f99f7-8ff7-4d42-a726-191c050b2b4f', 'TAP154', 'TAP154', 'https://search.google.com/local/writereview?placeid=ChIJLfqIP8brDzkRkt0HDCdsufA', '$2a$06$o06GgADp9VkR76gxOD7z4OBQ/V293WapDiTRVsGEU9VF6uFtp5UaW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:34:10.063011+00'),
  ('37886588-6041-4fc7-8319-e9888564d796', 'TAP398', 'TAP398', null, '$2a$06$jvu9cx6sxuzl4tKs5g0HjOOwFt0R5j4q7iAJc3IEUiNEGnwXNps1K', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('37c214e7-7c0f-4fdc-8085-f0e848575491', 'MTM418', 'MTM418', null, '$2a$06$gtQ/izqGYHtY20VxNvd5aufeyPG0fuJwWbXuJjOn4ghB2.6VlXgv.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('37c7e17a-8c65-4e3f-afe6-a651162d4292', 'TAP272', 'TAP272', null, '$2a$06$1zmxJATxI1ANqpSWe6OMjO5/mrsYIIAQ7RWPd./qkDWi2TQZShE3m', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('37d123e3-b961-4a9e-83e2-aaeaea01a642', 'TFF421', 'TFF421', null, '$2a$06$LiMG21pQoo9cBU0wuMHSWuFcf4KZ1eSdY6X2LfxOVbeFiVkOwoDzW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('37daedc3-439a-4c09-becf-504e38d05e18', 'TAP239', 'TAP239', null, '$2a$06$sZINXPZeRb44tZrJcSBAy.sTK0ufS3XZuJisOvr43c01PuvpQpw8u', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('37f11893-aa21-481a-8ae9-1633df63adb0', 'MTM235', 'MTM235', null, '$2a$06$LNdZEMzo5pc3ZmvrRR1edujyPCQ3dRIIUCIKF55uDGCAj6BXHP90G', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3811a5b9-c83d-4589-832e-8b2a0893b470', 'TAP180', 'TAP180', null, '$2a$06$MPHxGVNsxSFJS0IWi882JeXyynPAwIKnspCc49zZEheG3fmHtqnjm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3812bed2-e148-42ae-855c-44dca900d166', 'SP113', 'SP113', null, '$2a$06$Dnm7PAuYHbPHRdt6nUwn2evzsomjJQhTb2qN30vh5mVv5LqKcVRUO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3850ee2e-b92b-4e25-8301-46de1bfd317d', 'TAP165', 'TAP165', null, '$2a$06$3JJUPpZ/KiFfRsNAuYRn4uRq9wBnw5K02evI.Dk1HpnBvonZZfRC2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('38516523-59e9-4a3b-9211-b6694e557249', 'TAP339', 'TAP339', null, '$2a$06$shwK/a3cjRQCrmD9SP3WOek7GnAFFMr6ugsoUp9uKmr2rtYQcvDiK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('386f9921-4cf5-42b5-a2fb-d3f7716f2bc7', 'TFF272', 'TFF272', null, '$2a$06$xwB1u7NgXggEIsU8SH.OCedZlmc92wab/CPaOTep7X8inUwkmxZTu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('38a99bbc-fbe8-4a4a-978a-cb2132289cf4', 'TAP145', 'TAP145', null, '$2a$06$iOWQbsuL7UCXIFXW37dYUuOlA9zXU800W5Dv9atrwQSLKOpAQHZ/q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('38fe883e-4838-405d-a435-73a1bb007ee9', 'TAP083', 'TAP083', null, '$2a$06$fkhafoHfBZBNuj23s5W1tO7vsXdHTpbduheOvonDjb7biWlbuA.Na', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('39253419-a146-473c-b614-0de14902ae84', 'TAP308', 'TAP308', null, '$2a$06$.P2etUj76ivrkGcq1V7cYOVfq6v7YQc3Us71p7M6vTDs8bMuoIC6S', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('39572765-5baa-4131-ad60-b065f8aeeb2b', 'TFF288', 'TFF288', null, '$2a$06$VMtA8Bjk9SZDBXYZfI/Isu2jxfrWH/RXtUlI//KsjtR.XtWKdQaf6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('395f3710-9b70-465f-a4c3-269bca5c7cc1', 'MTM222', 'MTM222', null, '$2a$06$JUnLumZQpfDX4c7.QRJp2./2/RlBES23iVJGhpSc43hLk4DoVqCkS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('396f54a9-231a-4972-9974-31d71fbdd652', 'TAP392', 'TAP392', null, '$2a$06$0jXNPxR6sDDk6lZuNjl63.CMEno9Ul88sDBoiqthHHP1K0AJAijJW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3978d0b8-7f0a-4023-abc3-696961f07c7d', 'TAP110', 'TAP110', null, '$2a$06$lI4Gr/Fvx/9kuWdXoe1Z8O41a6EP2S.XdDB1GegllNTY/E8BNO1Sa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('399355ee-ba59-4555-ad62-aa0453f7cdba', 'TFF420', 'TFF420', null, '$2a$06$Wy0AtdidsV.dy7TrxdF9N.fcrbKBbiqoqS3qe3M3IskHhZiKuUg.G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('39a3e381-110c-4162-98f2-74989fd472a1', 'MTM450', 'MTM450', null, '$2a$06$pgKGSA2v1T6jv5URiLrNq.sGXpdeFakPL8kmfakaS/K4Qr9XFOH3q', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('39f040ad-f02c-4589-8519-1a49bb47e9c6', 'TAP214', 'TAP214', null, '$2a$06$rtGqg7ulKC.wUjEHh0Jd4.KimdntDVSrctF0cJr3Tqmi0Bb0itzSC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3a094803-63fa-4a7b-b256-9c657de747b1', 'MTM309', 'MTM309', null, '$2a$06$EfqeSipEZT5V5ChCNuPBYei1aT/UbL6TqfIrsLPkWCM/K2jOwvBYu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3a0aa881-9543-423a-9af3-fa5cede95874', 'MTM206', 'MTM206', null, '$2a$06$dkv/CZ8vDao0WA2eCRORPeIRYQ4SMvEK/4p7tu8Y/B58S9153YGw6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3a103576-5e03-48b2-b4a9-ef8769fd222e', 'TAP174', 'TAP174', null, '$2a$06$8Tf33j5PyfgaUWjpVyuNMu.UVD6SRWwYy6D.F480KVIv0iHpmgleO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3a1de576-ba63-44ba-be3d-2b7d0ba4a1bf', 'TFF469', 'TFF469', null, '$2a$06$uSaRzOID5W.DotWFCVFeTerSipWDVLoNRmJqH4ltQL3fcdHop7ZOu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3a7c4d11-1c8a-4b10-a82b-63bdf1af3cfb', 'TAP216', 'TAP216', 'https://search.google.com/local/writereview?placeid=ChIJJe9EFzTupzsR1C2gDcUQlT8', '$2a$06$UUk.YYjvLpCawVP6C98uWuffX2jc20SOcthuIwoHWwf2BI4YW0t3u', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:06:37.26335+00'),
  ('3a8045d5-9388-451f-9ba5-aa93d8803a04', 'SP344', 'SP344', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('3a838b17-3799-4983-a922-aa79ef124ea8', 'SP244', 'SP244', null, '$2a$06$wqj1HcZPJxt6h0ehOyF6x.8iVR3wVBAbX1y9zFunMqk38ftCH6oE.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3ac505e2-a25c-4b54-9b40-c826e204b76a', 'MTM408', 'MTM408', null, '$2a$06$kRWKNX9WP1qZ0kH8VZE7guPtIE3BqIhtVVVYOrRiMV9ciDc4cbJ4a', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3acc6a81-e333-48e0-a273-d74cfa8d70e6', 'TFF440', 'TFF440', null, '$2a$06$rt.9uhC2ZiVp5WYepe4AnOOMnzHwZ9Js73AymNAf3ARlIGkWBuckm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3acc7790-e4f0-46c7-bee2-0b87161980df', 'TAP340', 'TAP340', null, '$2a$06$P1/RTL1th8R/Zy1dWZQ0GuHHhFv.TnUTLRU4HHQagMQwnHr3dZ0nq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3acd4f52-0422-439c-8639-db2f57a0440d', 'TFF019', 'TFF019', null, '$2a$06$6BM02lvV1ysdSlJTqgTEtOI4i5zSnb0llxYtpPRwtQvtCbCemPycK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3adb506b-f398-4198-9a38-ef8640f74f42', 'TAP238', 'TAP238', null, '$2a$06$M1XvBN7BmmA3SiQLJrX0V.aJL6L2IVSdNYURF.atcONE8xoyQIHq6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3adf3644-c108-418c-baa7-c904fc4a6352', 'SP116', 'SP116', null, '$2a$06$ltMXxzeeI6cugmEcgGRut.dkssWYrPWutLyfg04VPUhyocmFE.vb.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3ae7b3eb-dc34-4e3e-b950-4f20a82897e7', 'TFF032', 'TFF032', 'https://Www.google.com', '$2a$06$ctIFntgSq1tvkVt7KRMnE.eNV1/t5xWQpemKAOXCSVBHVIBygQmzW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 17:51:33.517317+00'),
  ('3ae9ea2a-a071-4d82-9f4c-55705f3f38dc', 'TFF226', 'TFF226', null, '$2a$06$7eB9ZMBlWtECFSk1BPwA4emfnO.R6Qkh37P3Msnv2DHyv30SWRU5C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3af8ae80-a3e2-4a75-bfb1-f7c6003ce560', 'SP457', 'SP457', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('3b109983-e3c8-4a48-91d4-fc47066d7a99', 'TFF300', 'TFF300', null, '$2a$06$li7.MFs5NWtu3GncTGifQOjNMerHSJUiLm6fugdqsWYGOxirVOX2u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3b44176c-5b3e-404f-aa2a-d1b4cb0ef594', 'SP356', 'SP356', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('3b441a47-2a18-4bc3-a462-401765e0f1c5', 'SP049', 'SP049', null, '$2a$06$X4.uDNDmR9Wo.jaFKgwwfe8liTf1UUJAGUgWY/Zzq5xuG5k.3/vk.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3b4fe938-f378-4048-ab99-e836bc10229f', 'TAP158', 'TAP158', null, '$2a$06$alMXThRyjbPJHnRsZC7HK.lU277WVB0LQiDVNrBYxnadMEl/QeCO.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3b6d4dfa-24a7-4226-9293-66de5999f3a8', 'TN22', 'TN22', null, '$2a$06$3kTj0rTEBjbcqztmgFthZubvBuCB//xgOQ7yyMFXWp0X3sZNA76PK', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3bbc6490-dcf7-4c3c-a24f-c17759fd30b3', 'T160', 'T160', null, '$2a$06$shDpkJwccH3bJrTe4eiEcecOeYfqTRen4ZRD7nCT5GQUjsi9E9uWu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3bd7965f-cd13-4916-8a85-b1bac41ad2e1', 'MTM187', 'MTM187', null, '$2a$06$0/ulXb.K88aPFJmYwqNwj.m3JHB.YfLIoX1907TcMpqhp8HTChAYS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3be479cf-1e88-471c-bd1b-998d9e2e918e', 'TAP002', 'TAP002', null, '$2a$06$9JdejFQutPsS5Xs5XmR8N.6LHZYfq/rD2M7ciDMWRJEehmoI7SIRW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3c485034-c273-4eee-9ab6-9b5c20df96b2', 'SP470', 'SP470', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('3c4ddefa-e613-4b4c-b0a0-411be28fd3a6', 'T131', 'T131', null, '$2a$06$AofMtlgLrIk.xNzS6JnH8.8hjqMEouyiVL39RDuWFDKe3u6oWpfoK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3c650048-f12c-401a-b134-530516381a6e', 'MTM347', 'MTM347', null, '$2a$06$W8Xd/rG.gFt311VnB9vgEew5XhRUofwoYkAY/Np2u2tRadnslHNxe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3cd57c24-f11e-4cba-91cd-1322e8da7788', 'MTM230', 'MTM230', null, '$2a$06$xCnC2Fo7qK6/dUfL69idguV71HW4qansi.zn.u0rOgpYHsc0i3Xg2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3d2ee606-9ec0-4123-8784-29d59c1b7f55', 'TN06', 'TN06', null, '$2a$06$eZsnRn9AVX/ad2oo1izKIefVaWuQGfSrLJH2u77t9LSTbDa.B/9mi', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3d453f76-dfaa-4248-8c10-6ade99ef3731', 'SP175', 'SP175', null, '$2a$06$DA6EPLeAQHd0KqDcXGwzOuMgybWdvPT812L9aD1EWDSrSG..RvK4u', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3d794bac-fe8f-4b54-bbea-fb55a5d13636', 'TFF349', 'TFF349', null, '$2a$06$eEUqMl/QzYJ.iSQpedc8TODUeokpL.Dp2Dx3pHYJwDpB17iq6CBQm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3d8d93c4-3182-47d6-ba64-16e6b5a830ee', 'TFF186', 'TFF186', null, '$2a$06$L/gkgQBADTLeg52ycCFAhOZ/KO..ERqBGwGH6Cbn6z3nMpFl4EbA.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3dce4e17-9663-4a70-817f-7e2d4dd2e536', 'TAP173', 'TAP173', 'https://search.google.com/local/writereview?placeid=ChIJ3UBNn03rDzkRQtnWMh08Xrs', '$2a$06$liu3C4UpRLAzEg9TxmInyuliyBg.uPkp2EKz/IRxRB46XK6uUZ5NO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:50:00.797259+00'),
  ('3de20783-d44a-49b4-a438-aad3d9c6341b', 'TFF394', 'TFF394', null, '$2a$06$oG96LdeFu1DshoiRGaa9yeexxDEP28nXvTQrxFpNbOc0VHr6CWCna', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3e495231-1fdb-4028-a9bd-58364efbe772', 'TAP394', 'TAP394', null, '$2a$06$ELmyEIsiKDztFwmHz3cFoONTDUmkx2Q1.ueYsgYJErmbk5Y97F/RS', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3f0dc528-70ee-443c-ad17-3ee2152f6244', 'T243', 'T243', null, '$2a$06$yv64oh3wG1bxYckSmDgSLOsDpBJRuGEeXgZ22pHtLzog.RLCHIrXa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3f368470-b50a-4c9c-822a-495e427e3793', 'MTM281', 'MTM281', null, '$2a$06$BWNeZyyVVe72dFX/7xJTS.bEQoRKC5lxJgG6fvpogcWttrGq8F/UG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3f47fceb-c32b-4b4d-a078-08782d68973c', 'TFF151', 'TFF151', null, '$2a$06$4qVcl9mGL2OVNFMWtKMCHejVnPqwdKe8FGz2NLaxEo3LFIAiT7o9.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3f79dbab-736d-4590-86c1-91cc55927d96', 'T056', 'T056', null, '$2a$06$33v6QnJJ/0L.jjZJTpdNLuyQYDwK.61MtUWIK6mYuZguhUkF7H9/K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3fce432e-26cb-4aed-8d61-5d66a720ba20', 'SP361', 'SP361', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('3fedf8e0-c8d7-453e-988c-20ad8aebbcec', 'SP074', 'SP074', null, '$2a$06$mAOnLvTISnYgf9u.akXFc.QHORj4AWppNduZAfYgNdZNWbSBGiSL.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3ff746a2-54fe-471e-8650-d7e5d49da2cd', 'SP247', 'SP247', null, '$2a$06$l.qIaAvtLszj8622ezHq.ecjXNldP3FK7ZcXVdAOjvjqOVEKtVleO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('3ffb4d67-6558-4e02-bfc7-3fd91645ec3d', 'SP423', 'SP423', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('400a2b71-deef-453b-a8c2-19b4a3fb1d65', 'MTM157', 'MTM157', null, '$2a$06$kVjDxbOBxiPXDYUYPraxZ.m.FxPeQ7UHor9yMI9eYrYza9S6gu7k2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4016be4c-dcb7-4c72-afa7-dff786edea5d', 'SP107', 'SP107', null, '$2a$06$ZIx5QtBoWUc//YvxUdoyLuraY3kHQAoumbMO5INxAtPd3szHtwChG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('402a4639-3f2b-4314-8d7a-a8b56dc08440', 'T188', 'T188', null, '$2a$06$.f3kQRihZnZ5boM4bXuhJOFtLa0FLYo/TjVqFihRd7mJfph37XB2u', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('40326b07-f637-48e1-a636-893e9b88e9a9', 'TAP367', 'TAP367', null, '$2a$06$99p55HS5Jf3ursqj/mHex.vATOgz0KPosninqCfhhNciawAJQZZQ6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4041b418-4d1e-475a-882f-4a0c2121c6f5', 'TFF254', 'TFF254', null, '$2a$06$mCfIuXdzcS6.X4ZU4UXgsu0umBj.txJbuNdogneNy0gXtWr50gXTq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4081f0f5-f0da-4bf6-91b0-2e8945f743d2', 'TFF333', 'TFF333', null, '$2a$06$W4YkDiKsccGrWS03flKS0uZ7h6XLrNfLKwY1TL5kRrlQCKMuIzO46', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('40a74c0c-b1a7-476a-8d4e-8032b208bd3a', 'TFF115', 'TFF115', null, '$2a$06$ooBLWEKNyax/4UsA7fNE8.SVr6ht7lR1zexm8GQ4zjBR/.T4jiwr2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('40bad22f-857d-4b89-91fd-8c6876b2bbd4', 'TFF149', 'TFF149', null, '$2a$06$IQXEQxJfhSb0s66tQiJyRe3eyYnurxF/scLFfzJ/a5wVqfVT1XSEq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('40cf3e4d-c0b0-4477-8fe0-8a7323a91d25', 'MTM306', 'MTM306', null, '$2a$06$8rWvsSLDYzy3KvZTyedJ1e5YN8sgwHLhlsLC23LpLoEd.W5tSRKvi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('40d6c540-177d-43a6-bea2-bb604bddd4b4', 'TAP378', 'TAP378', null, '$2a$06$SbXTf/d.v5OIyhMuDl.XOOYJouInfDn74UiK4AFzjdYFeYNrnMLB6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:23:51.336038+00'),
  ('40fad099-362d-44ef-aed5-8d49c100de75', 'TFF201', 'TFF201', null, '$2a$06$ckGhht3dnbHOj288ZeXomuDSFKz90ZVnYT6wmYt91jNewd/IZ9MXe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('412448e8-f552-4eaf-9f96-58da452b7388', 'T276', 'T276', null, '$2a$06$rxpMQL3NdXXYfQ8AqZb7D.4Z.x4iG29.Jxddeb3xa/68rRHCD8T1K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('414c8a1e-80b8-4871-90e9-137ed6965576', 'TFF397', 'TFF397', null, '$2a$06$0MbmiMY7xY6ufcH..tia2.gp1AQ6OUYuCRI3JXYGA4GrRHuCMenqW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('41512e5a-9247-4287-889e-5db8c16a9490', 'TFF237', 'TFF237', null, '$2a$06$Oh9pf7JmzYK/TDAuPSlXfert74j.TSKvXOZdIbtf0fT/p5D6rUiW2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4162e938-a000-48f0-913b-8ce0d05f4e7f', 'SP166', 'SP166', null, '$2a$06$pdKTrXVMkqbQ5YS9hUMms.1ktcrNTd1Hc6KTQjpQpS2qsk8h3Suu.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('41b0f5ca-53e2-4dfc-8eb4-4a656ff479e5', 'TFF309', 'TFF309', null, '$2a$06$RXNadHH2rXEOTXzCcGGZmezESVh0yWurg/69FkfyJV7DuIPwlIaWu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('41bc4938-5e22-43cd-8abb-87e58639c935', 'T210', 'T210', null, '$2a$06$WSgHoWeDBi1.eH.IoarSHu30yASptURAsYRoryP/4Lms5n6cNncUq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('41ca26b2-499a-40fc-a012-47ba23998681', 'TAP226', 'TAP226', null, '$2a$06$4ag0NQcg4p4wLgS.y/TvWOMjvSHeXvQp.63ktD..f6cfRM5b6NAFW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('41ff8980-a944-4217-8f08-e07fbf8ff9ae', 'MTM147', 'MTM147', null, '$2a$06$2FRR4o6WYMDJ.fou52W5HuYFztB3CF9/Tm8wagmZrR9lBreQesNSC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('422196f1-c56c-494e-a030-19df14dc8330', 'SP234', 'SP234', null, '$2a$06$xdMfcOUnsDyvuJ2n5uLoo.WIOGWnReKbqjN7U/lAM3u3fIKSKJWsy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('422aeb15-dbf5-454f-bad5-dce6d5991300', 'TFF078', 'TFF078', null, '$2a$06$edqk7hbNf1e9iS2EEXPKhOWzpxcFMpkEPjziXuTnGNT/e4j2j8JVK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4261f358-076f-4bd4-b97f-e1d2a6448aaa', 'TAP010', 'TAP010', 'https://Instagram.com', '$2a$06$.S5ck6HEVHxIgBSC5WgvdusXlKLDpd26xsUbsCttJjRF1eV3qVFw.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 06:52:44.576147+00'),
  ('4264fa80-aaf2-4f46-801f-6b9ff30a6518', 'MTM439', 'MTM439', null, '$2a$06$tB11DyaIKWGIg8TR0BOHhumD7cPAY9HlPPxd5IsIGbU.9K4FGQlNe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('42bdc8b6-a673-4e6e-a131-595b3154936b', 'TFF148', 'TFF148', null, '$2a$06$Zo.bTYXTj/qjlF1QkemZIe5QjHx4yugkf.wdnOddR0DxBYG0S5YSK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('42d29f0e-aa05-4351-b8b2-085e607430eb', 'TAP202', 'TAP202', null, '$2a$06$Bf6mPrieFypSTDgSLanzretSxBtSxeJI5tspx4tZsPIJ7cjvCwU8.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('42d6cffe-2c2b-4b14-b0b5-22b3aa10f7ae', 'TFF433', 'TFF433', null, '$2a$06$agmfkeVjiXbzN.r3DsF.5u/NzBtq6MHe5rJSJotEMJY/OQ3NFsnnK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('42fc2fb3-5575-4957-b05d-5f5665c99bca', 'MTM385', 'MTM385', null, '$2a$06$9Gut.4a45EyZeJUkDutvd./haSCQc1N/YkvJ651gasZ9jQdvtbc0a', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4309d837-ad8c-446d-9f4f-773afb4a4b49', 'SP115', 'SP115', null, '$2a$06$2nt1FkZ3AaJwc5SCft3Bj.Zgbo7sKzXgdDq8R9BJvgdXZKmPMOenq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('430ea682-80ff-409f-bb1c-8c5b4a830ce6', 'MTM398', 'MTM398', null, '$2a$06$cLhtcTZupH/BQZtnnXTEOe4axhEwHCMlF7UVcZEkUPvITbwxMQnYS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('43188b34-3182-4209-acb2-52405e52bf84', 'TFF156', 'TFF156', null, '$2a$06$b8t.c1SY.Tp26Q7SrxffE.eNKyrAkyDLgC1UpO5Y12c12dM3i9Au.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('43405750-0108-4f24-b60f-8668a465ddca', 'TAP399', 'TAP399', null, '$2a$06$9KkyrVweL7RD.63Q/SIiROcylc9pVyov43PyH5QCdZ6iNOIFcxFNa', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4340fab9-dabc-4eb8-b06b-489cc36dee06', 'T098', 'T098', null, '$2a$06$ZYrmZoQGA4lG4dL9B/i.wueDa1FrP79Kohy5DMskrVUqNLugTGkui', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4342261b-b947-4c93-9b48-9cf461949793', 'TFF413', 'TFF413', null, '$2a$06$fq5zp1Yad5i/2xBIIGagleTTQMGgtCRmS8CtYcL6qPmRa.t89XEu2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4348b051-9652-47d6-a48d-77f81712ecfa', 'TFF080', 'TFF080', null, '$2a$06$0Wktd8IOYL0//t.QbQD1/u55rqBvlYNe0L9LE.MyZIFD51juuxOM6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('434a83d6-b995-4d59-8419-2357f0157726', 'SP424', 'SP424', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('4355e85a-8fef-47d2-a25c-7954d402fa09', 'SP144', 'SP144', null, '$2a$06$Qcy2bMIJfPi/eErSrzNT7OGNwWQVgvoaKZFyN3Cpmha2fuyj2GcM.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('435860fe-1033-4787-abb2-63117440cccc', 'T162', 'T162', null, '$2a$06$RCVyJHk8JrhaCvrqN5fX..ASiSfG0Z0dUKHEGUlXTYTUxwU86xtt6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('436de469-0c5b-4d72-82ae-ae833a838afd', 'TFF262', 'TFF262', null, '$2a$06$G1Dnrq.2OsOMunIbXb6NT.28bAnCsl37xan26XD6z7t33/nAblY.S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('43964c4d-45de-47d3-9369-1142d86e55b5', 'TAP124', 'TAP124', null, '$2a$06$8IImTDicF2AcwV7FgvdV.OaNv7oejZEVkiCJX6QklcpSbMSxZ8U6G', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('43c0386f-ee35-4811-8f4f-7df003f92248', 'SP471', 'SP471', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('43c7995b-b30f-46c5-ba11-4ae0c3844b5b', 'T258', 'T258', null, '$2a$06$1fXeLd77V43D47lkkeWsc.mBiWtipF5HrEsybYXAOzztzdf9LM8xS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('43f2d275-dcc1-486e-af42-d7a2ec3c9402', 'T045', 'T045', null, '$2a$06$gbwRipsmSrEUc7sbVxoRvuBLQy/GQtiXWMs4V2Np0JhB2yjEkZQsO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('441e4956-ae05-4692-9bbc-9a938c64390b', 'SP324', 'SP324', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('4424445c-59f2-4883-af1c-eae3b13e13f4', 'TAP080', 'TAP080', null, '$2a$06$yu6Wsr/2fFJaR6kNCmSzAurtHEV2aD1Rs2gQvtKKLr8RIWhbW0R06', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('447b3dc3-4db8-4e9c-a9b2-089fbeeaac85', 'T286', 'T286', null, '$2a$06$LNgXwvV/OMsR1UvAUmOdYuW4VE9lbYNF/R9Y9.6pqFRtPcqCgrZ46', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4480982c-aca8-490f-9db1-6b15d4785a25', 'MTM288', 'MTM288', null, '$2a$06$dWnwZJ.OIO8GuC6ssa.vAOd6ZtxBeiJkB1uICK/EblXitoFf2ez3.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('457fd05c-dca0-4bfa-b3c1-1517f78ec733', 'TFF132', 'TFF132', null, '$2a$06$sPKQcmwBWgh0hTR51e.cPeRe094rTEFiY5pVodqUoFGozMkxPBj0y', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('45d812f7-f7a1-4ac1-8d80-a79e837273f6', 'T048', 'T048', null, '$2a$06$02ss56G.ZO5TiEacw9bXx..ZQx37tYYV8ZiDrj7Hzkib6ySRstxWm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4602c5fc-9a90-4525-ae51-a46a6a85b632', 'T040', 'T040', null, '$2a$06$TYZF54P/XeOzotJD9J9L/umnw4aVne10v88UyOwoZ9n.63IzR6PYa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4617a9c0-85c1-4549-abe4-4021ad3e7fa8', 'TFF441', 'TFF441', null, '$2a$06$a9BlbS7Lltcj/c.XHZ7MIubevhzGTllGSOEXrnZkyvYdFv8l4Riu6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('464914ec-85af-468e-a586-1e7edb9dcbea', 'TAP232', 'TAP232', 'https://search.google.com/local/writereview?placeid=ChIJO1tYOQLrDzkRVjK539SixKU', '$2a$06$unRZhZ8rMAnvYgukxH9mO.52/XW6u41X3tXS42m7tinM1pM99jXtS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:39:47.706244+00'),
  ('4662d14c-79bc-4796-990a-9adccff3e09b', 'T037', 'T037', null, '$2a$06$IA8YxBHjIvb9IQcg1IZcbe1Yr.z/BHK6aN6EcVOHZVEBI5u6K8pH.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('46868a92-71d1-4311-8560-7578afdde900', 'TFF102', 'TFF102', null, '$2a$06$6jT1GhQsGnEY0DO6VRFpFeaDOZjvRGjnBNv4g5dwMEntORxoeL5zC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('46a1dc71-6fc5-4344-ac35-4e17a890d3db', 'T029', 'T029', null, '$2a$06$DDgilMwbnfAH0p18OYcAI.yrfzFt8eUKZRA1YidlUrOTVF20hQEPu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('46b647c5-d01b-492c-81f7-770ffb6c0453', 'TFF047', 'TFF047', null, '$2a$06$kez5ct.Y7S.oAQXYQupX8OjrWskrWYPHU90LJScOBrffWU1Cqb4f.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4714a95f-4cd0-4534-9260-3cb6dfdf4d16', 'T255', 'T255', null, '$2a$06$7bRJ8uXPCu1Ut38ZABnpUO/odl8QYYW5kLIvkL1OOKNlmZkq5MewW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('471f5858-432a-45ec-8e2b-a8be0532912f', 'SP173', 'SP173', null, '$2a$06$JcO.RorHL8rt.2w5iqkih.aV6TxE91rx6ISZCYZl3nIPlzv.5haRe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('472a5cea-4bb8-4e6b-bde6-b3b18e1def1f', 'MTM447', 'MTM447', null, '$2a$06$eRzZreGs7NZqTu6ctD7TLufsrcuLviVvt/MdX.GQ55eLaZtlsB7Ti', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('472a9765-1453-4016-9403-6f5db88d5c9f', 'SP300-SP500', 'Spread', null, '$2a$06$KR1fLh.MJEfNMfKZkbGeIeUiIYKYozv/HNkIp9cDhgcQEgu/wuhl2', 'active', null, '2026-10-13 10:35:30.281605+00', '2026-10-13 10:35:30.281605+00'),
  ('475015b8-f1d8-42b7-8087-cf9dfa3d302d', 'SP024', 'SP024', null, '$2a$06$6RVdONozvc4jAZBl56FFDOxYveTFdAtCQsmp9iMo6wGRyf3s2O/Vi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4755fe8e-abdf-4c15-ad3c-8d9fb9850f6b', 'TFF351', 'TFF351', null, '$2a$06$mzzQKXojG0JLRT8cLdZ/D.6BLgRY0qMSs5E50G4hDUXZoIoJqvYxm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('476584ca-73b1-4a40-a038-545fe96705fa', 'MTM323', 'MTM323', null, '$2a$06$g7oxUGPxLBkvrAl5l63A2uoVTT9C0.7mSvda5W7OxJlNdpnB59MVe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('47820f39-75b3-4785-840b-e51b1c94db9e', 'SP410', 'SP410', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('47ae75bb-87bb-4c7a-a131-9e343ea618a5', 'TF10', 'TF10', null, '$2a$06$besGw7eFoiJIiAAwMXWS6OWiYaCXeKGAssAMYvJF29AleffNPLx72', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('47b9d957-09b4-490a-8145-2d8c32e99958', 'TFF447', 'TFF447', null, '$2a$06$VvIzoCS55GD1ctI7Hjfq4eUcrlXiSIVaq8.jlYQBw3s/8cgswOKaa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('47c211a3-2862-4c42-bc41-be2d86ee3d0a', 'TFF387', 'TFF387', null, '$2a$06$DtHyCwfHTAgRZykAnbYbpuz2pDnCiEDVrs2oJACgMJcRFg4wGKuLq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('47cbd9d1-c4c5-4e0e-85a1-87435c11e840', 'SP353', 'SP353', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('47ed4031-b94f-4775-92e8-8b30202c4b9d', 'MTM200', 'MTM200', null, '$2a$06$b/17Nmn11C9nBE9LutkpQ.8QMXjbjge434z5oc1nhs18EOItF/DCW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('482f8784-d4b3-423d-9a77-ed0703ef9806', 'MTM329', 'MTM329', null, '$2a$06$rgLljX8j0HHcLocVT8I3n.xuvIH9UAIJjEFOLuph9X94Md/JgsEPK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4831bac7-ef4c-4acd-964e-326e52f6cb56', 'SP479', 'SP479', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('488b497c-2dbd-4cfc-b476-4eca36d4f4db', 'MTM296', 'MTM296', null, '$2a$06$7iEfKATfZefsjvcWJQMAC.zAQYB2XV.MLniMXovS6HqRnk7dnH2nG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('48990a1c-91c1-4d42-9f36-2480d3fef380', 'TAP175', 'TAP175', null, '$2a$06$wkspog32CdTkKBZjJ8yh0uRVgC.Z9T5rASShdSJ6DHdd.EJqpuCai', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('48d42c59-9607-415f-ac85-d3c82985acc5', 'TFF481', 'TFF481', null, '$2a$06$pD7yhow2bQYbEvcwv36pkuVunYopjSmWDyLuoOUmDE/Ad6CbvKKsC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('49191824-9ee2-47e3-8dfd-c1d64f3cc147', 'TAP177', 'TAP177', null, '$2a$06$SmjtxOWkA72dNzkWf7gUmOthjEDqXiN4UavgiuSy7cA.NFWHsCbXW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('498b4ef9-f8a6-461b-8cfd-5b64f91786c2', 'SP033', 'SP033', null, '$2a$06$HbtXRehHN0KDQGDrTq.YvelHc/kqg89FnBGZYCDtNKheYW3cnt5/q', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('49a79925-e5c3-4267-93e8-a8d684b28ebc', 'TAP041', 'TAP041', null, '$2a$06$G8L07IthhToEmYZ.xwZL2.g5eBiamPCwA8cDa3lnWQ6e4PVMds1fK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('49d6991f-174e-4654-bae9-05719b0c25fd', 'MTM389', 'MTM389', null, '$2a$06$5WtBCfD04Y1j75jhGlEvLu/AKeMzQaSc8pQJ0Qzm49HoVFqVp7KZa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4a072514-446a-4cb6-aa86-59bfdaa6383a', 'MTM132', 'MTM132', null, '$2a$06$NDIQ1pL19Iz4Po/IxxuedOSs9vhJxlTJNDo3vHjxAYmrZYm3H7Zia', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4a9eb832-569e-4d2e-ad62-bf1627ea2aea', 'T250', 'T250', null, '$2a$06$8giyYk0ZvaBUpYJPRj0b8uONGUQUE0yfwCaCNqrVU6PJ5dPQq8f5i', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4aa18de0-7f47-4b29-9651-3fd168d27f16', 'TFF058', 'TFF058', null, '$2a$06$OIsgs1gTQDjhLhOTE8yw4u4s2NErtIZLz/JMaYqV7wzyDESEQd5oy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4ae3ed84-0f42-47d0-9563-7cc4b83c9d09', 'TFF141', 'TFF141', null, '$2a$06$z4scgWMjLMQFz6HOg.V0xuhczTMtWh1v2UsZFOWyS67L3QQhT3axO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4b27cfc3-24b1-4e08-9a36-f709e8e5f6fe', 'TAP322', 'TAP322', null, '$2a$06$6dXvMrWKIroNsFRzZ7UkzOzge5rq5VWqb.0UhIrViE5gQZyuPxZsi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:23:20.160348+00'),
  ('4b4d4c17-c8cd-4290-9980-18b41a31b95d', 'SP455', 'SP455', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('4b628d83-9f3c-42ca-8970-a78b3148ef43', 'MTM298', 'MTM298', null, '$2a$06$6m5erGjNQ1fvUkkKruH3NOfkbr3tCRs5Rk7zA4oZiYLLEy/Ir0uH2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('4b74be6c-ff74-4daf-8f66-5f795f62a2a0', 'SP035', 'SP035', null, '$2a$06$/PXIJ250RlNZ4egz6jkose/Ez16EMb/MxLX408PMYquJiJfuAyatS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4b92aa2d-b435-42be-b829-039bd7a3be30', 'MTM386', 'MTM386', null, '$2a$06$B5FQvg2IgpiFaogTG/rkeOijwIDIhEuFqJeHuDJkhUWAPjPOs1o3i', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4ba20591-2633-41d8-99e7-b6fdb8886ea3', 'SP288', 'SP288', null, '$2a$06$I3CoPcVPlHTKwVGEHypVkOx3nj5vUF8AJwdYLv1TirnQqwqYn.5Uq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4baf57da-4646-4456-8205-765f1a182162', 'TFF100', 'TFF100', null, '$2a$06$yXZwnBW1YhZtfTimpIZ/uu3xBP4bGbuGmyj5SuFdQ3cayfiTkw9Ae', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bb6cbea-0184-4fba-adc8-2042f445742f', 'TFF274', 'TFF274', null, '$2a$06$5rX6.3Qy8.dut.6jTsRnnOiGFuwFf4H5Se/AcA.244Ujt3yt4Wpsy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bc223b6-1285-4a71-a17c-5638474e88a3', 'T042', 'T042', null, '$2a$06$jad.7/5kc92lmsM6ruhyROpasUfG/GUV.1r2LB15gkQx7aEOnvSWK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bc5fc10-4ede-4385-84d8-7a4cabf234ab', 'T145', 'T145', null, '$2a$06$5uFSaluEHXMbYqR597nZUe2HoMf20gPndWylZq47KyAxbzWM6ilJ.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bc787ea-3fdc-4f86-89d5-0aed75f32d23', 'TFF104', 'TFF104', null, '$2a$06$yk/UV6rZQlabnsoEefT71uf4Q5e.1NtwVwCNk3Z210Ab4sZsn6KdS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bd8222b-7ecd-433b-97af-4417f56199fc', 'TFF345', 'TFF345', null, '$2a$06$rXyQ7tuIIRZMWOPwZU7qIOzLMDNN81FrlQZr.olLbgmsyFcozLhsi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4bfd7778-d52b-47cf-92d2-75b6edc6e8a5', 'TFF261', 'TFF261', null, '$2a$06$izA7D2xc4gOdtVNNBziDdeWTQk.8J8OS58KAsk5NpIZVSfKpt7JHK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4c223046-cf31-44d3-a5e9-5e77e51b2561', 'SP372', 'SP372', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('4c341e1e-c945-4e90-a3b3-301f956f869d', 'T174', 'T174', null, '$2a$06$7aHKSDWzwEIwFp/6eL2ME.KAUYNd1IkNvooTR/y/IdHIcagEfvdP6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4c96e4b3-fa52-400c-8ac1-eb6bfb259738', 'SP065', 'SP065', null, '$2a$06$rZ8yUhs.GNcOCREWD5dvYeHjkNEPkvHXAyI6Q37iT2dzGRIQ8PPTy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4c97bee6-3c83-491e-972c-7c3134f7ff2a', 'MTM197', 'MTM197', null, '$2a$06$5XyirHywhcL1bIuUipO6LOykbmBZ5Syq9t86BJfu9vdjr.dtA71Iq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4cb4d634-f8e7-4d96-b264-65a25ef45d1a', 'SP189', 'SP189', null, '$2a$06$296JL3Ejlmjt8R6YUpZ0Mu3sQtsmNrlA5L04ox90janl2PZFa/dDS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4cddc149-4377-4751-8a9e-c6dc9175ce8c', 'TFF443', 'TFF443', null, '$2a$06$O8pfKunfZvzSpkpD/iPAoeWKUw/doOEgLFrHpAekOKb1ubW8jZGrS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4cf70472-d654-4b86-8640-c8c59700ed3e', 'TFF240', 'TFF240', null, '$2a$06$FJkYgd6TWQLDNrU9ePAsf.ZRYc5pYCzaaJzgJiz9.NfNGYJL0Y6E6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4d186bd7-1f99-44bd-a889-d4cb882d9f92', 'MTM137', 'MTM137', null, '$2a$06$nmx1QBPrijGRfE6aZS6/gOrRFEnR5TSsA2u.KdSd6vPZOOTWH/tTC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4d2c6526-2a80-45f2-b05e-9706cd16c0fa', 'SP406', 'SP406', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('4d4abebc-69b8-484f-aeae-e986d48055a3', 'T006', 'T006', null, '$2a$06$5OsjdKbDkp2edjh5fcOnJeTPvlNxH046Uir93T3RCZz/rrbvMxONy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4d58aa1c-d7b9-4734-bee1-0cca860ecf68', 'T299', 'T299', null, '$2a$06$uPHN2C67SFerxO4gFRk5b.guDbBKc0h5DwiCSC8M2M82r/lF4fjA2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4d7ee81a-0834-43fc-abef-f7864bb7f8d2', 'MTM301', 'MTM301', null, '$2a$06$jWjbJLPVlUbrdQ3ZPIlElusv7p5J3ycdpgAb66C7oa/iyxtREAr6m', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4dc2a6af-4307-43d0-88fb-54643e165b11', 'TFF330', 'TFF330', null, '$2a$06$Tiwnk4proZCsikdZXi8YW.YQlqQeioKPPeabpHNYUcvBt3ySyyFiy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4de8197c-2757-409b-878b-a4a8f668286d', 'TAP300', 'TAP300', null, '$2a$06$fVTy9ByWymT8WBAtymR9Z.3.DF4Z1ADoekctRHcNfT1CoA3s13t.u', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4deccf23-1b8f-4b78-a3f8-ac626026e844', 'TFF025', 'TFF025', null, '$2a$06$hGslfdcOOAhYF3hW8QEKBOo3tFKFHRHL8qnr/NC6kQ9yEzkq.Q2HW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e450459-06e2-4eb7-afd1-aafc5969a67f', 'TAP329', 'TAP329', null, '$2a$06$RyUATDGynnMCsZFxV3yZle6nH7WCMobboGvJoT5ANJwUl2IeZyhki', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e63477b-4da6-40a1-adfb-deee62635f84', 'TAP073', 'TAP073', null, '$2a$06$QjPQBk8hstSpCXkdpaw6IO.FFcKTbdSL.9kKg.YDqVWpOJNKqH.KK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e6ec14e-6a27-449a-a977-84ff38f012b8', 'T203', 'T203', null, '$2a$06$ORTgrd1DOHReFbiL7fqFMOmoDc8QlW8h1uC.zNffVUzGnLmjpc3Vq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e6f8fd8-a054-47ff-a6e3-01817b88f5cb', 'T241', 'T241', null, '$2a$06$yXDaAcM9NajUlnahLw4LY.fSzyCoce6FnXZPzlce1hZC2U9k.m/Z2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e86b6c7-7e49-487d-9c23-3534fdb1df86', 'TFF185', 'TFF185', null, '$2a$06$YUPKcgQ1WGbarkDp.2nIn.6zknhvvgNJrxBgPUywgx8eWooi4.i1a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4e8f0602-8bf6-4554-aff3-593b9f9ad418', 'SP093', 'SP093', null, '$2a$06$LVZ7qLtJy5xWVaH.86NMF.8eFls2oiKhYUQ7/WJesF1LFCVJbEffm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4ea77fd1-99a6-4f29-a67b-568a19f8ded9', 'TFF213', 'TFF213', null, '$2a$06$Ep3yVwMul2KXkAogTIhwBO7j9xY0oei3HYZOXABrhL2zOksZ5.pdq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4ee776cf-2014-4a0f-a70e-ec79deb96c0d', 'MTM168', 'MTM168', null, '$2a$06$DBzMTYp4nGu.Lt3cfGA35.P5qscGIvEV.JJSkRhktgzaQu3QAgDWW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4efcf065-b283-4075-8d29-05105ab0d33e', 'SP040', 'SP040', null, '$2a$06$oO7aAPORcOA26sgNq7IipOSC.QFGMqfKk.VtNuwo7jnifj0/hRAZ6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4f0a70b5-e215-4f91-a6ad-c7fd589f62ba', 'MTM318', 'MTM318', null, '$2a$06$tZlBrbzFiPghziSE2v/rP.KRYuqMNoADD/WP5oWUAv7rc9xVSvtYy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4f2f96b6-641a-4bf1-acb0-bc20f3941013', 'SP204', 'SP204', null, '$2a$06$8E9TtJNVtmNC/QB0Nck.5uBDA7elqiv02Py/mtAq9isGuOKIvB0Qe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4f378926-ac6d-450d-bd46-56bfff8a7e70', 'TAP374', 'TAP374', null, '$2a$06$xGn9G5mRCmkLzN5a/6RNp.TUwePwRBbG9QkC5M6P5VEzMH8zl2CZC', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4f4809b1-3a7b-4884-97c5-5d34976090cf', 'SP025', 'SP025', null, '$2a$06$DQhUtnL8xDkzdmRtwYzL8uLc0vo8CUtNRYha4IF1zMCsdrHrH9bK6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4f99c15e-25ec-4030-b1c1-365e3bebb3cd', 'TAP309', 'TAP309', 'https://search.google.com/local/writereview?placeid=ChIJSVydOQnr3TsRhaQ9Jz2VDDg', '$2a$06$jVLjd2OxguTPm8UIeU9C5uL7hjy5aCbuazhU4okNYor.1VjfyVzai', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 09:37:49.849928+00'),
  ('4fb23c13-4b70-4c4b-9c86-f32d7b0bbee8', 'T178', 'T178', null, '$2a$06$4uMMFNs9gvnVDX.o9YVKOeotGKIowsFVcJQSGoKkGbo.iBT.M1eSK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4fc14939-6c37-43be-b919-7f876a112984', 'T164', 'T164', null, '$2a$06$xAmg.aZnLFG.3uKSxnDJLOHoYA/8WLv/4y.7piq7EtYkG.Tanzb8y', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('4fcd03a6-8eba-4aa8-8d27-f93c77f96130', 'T161', 'T161', null, '$2a$06$HLhe3vYWlT8VIfeUpBzeR.xGtnaCZgx2BTtf4KdmV8kNQOI.Q4Ene', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('500d4809-2c68-4385-a461-f3e8a7b1e107', 'SP039', 'SP039', 'https://search.google.com/local/writereview?placeid=ChIJn4Y4nuiw5zsR_bqPtVHvIAo', '$2a$06$bs59ObSMTfG6VxJy3LCdY.hKb5jRa8a0yNw2YUhFaL2a5zuQXs/CG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-13 12:29:31.715443+00'),
  ('501a6c75-d5b2-4ee0-94be-5c0cb4b2b4b3', 'TFF352', 'TFF352', null, '$2a$06$sdZZLdO2WX8utftkhgGsi.9k505OwmiP4abVUNmnLJE.YtLOoVEvi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('502124c7-5f4e-454e-be2b-63230f0b08c1', 'SP174', 'SP174', null, '$2a$06$qTa8cJ1Wgp3hrbbpTnNw5.YDCG18g9IbFEJ6F4340tRPfAc0TdALO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('50352d9b-a0f1-4aae-a780-ea75141d7855', 'SP086', 'SP086', null, '$2a$06$isqScVoFcmJMH2QaVunbVu1i3CRpE24VRjgVoZtCsGSlLe7sjcGou', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('505db8df-91bb-4a70-ba07-3d46268b21e4', 'TFF125', 'TFF125', null, '$2a$06$uPfX3Kxn.wt8GX/VfwZNTOZgr7bU3jOe5NZxBdBhu.wZ7888WT5v.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5076c0cd-c844-4cc9-b2ae-b5da02570324', 'SP294', 'SP294', null, '$2a$06$ztHTa4SOm/7BhBkCinGLkei/GIAlcwr38fsSpYWbhdhLRhh.XIKZO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('508eb236-edcd-4571-8641-c2b57d181991', 'T256', 'T256', null, '$2a$06$Pa.efBaER2QOiO5RqweCq.cbEz3lvmtrRofSOE8Q4308SZvCaNmam', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('50f5c8b9-c1bc-414e-842a-7aabc3afb60d', 'SP440', 'SP440', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('510e36fb-a27b-4ad8-a815-eceed87761f7', 'TFF154', 'TFF154', null, '$2a$06$Zg5xTHV5kTk10/JkFpaj5OKFD0eavkmfk3HA57ztysadEKXROfg4.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5150d35e-39db-4acb-b631-b2b12fc7f8e0', 'TFF232', 'TFF232', null, '$2a$06$/YGI4Cikvxyq.JpCCdxYr.pGUk8COl19W.onBh4ZdU8c3wDxdiVI6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51686913-8551-4df0-b31d-6b31e450abca', 'T236', 'T236', null, '$2a$06$8kkqnwa0I6rKi1qIcZv82uTDOQ5t0BBYqQgfjh3oGwf0t4N1wtYB.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('519fc4db-b5e9-4034-b971-06f31ac6128e', 'TAP269', 'TAP269', null, '$2a$06$h5EijFYz8fxUhtpikvdoBOTLYUC8BEZ80xPlITkPItEqT9hmIFyKW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51c42c02-d2b2-473d-9863-3a68381bb66f', 'T041', 'T041', null, '$2a$06$gClmGn60yiN80PMM99O2EuDKM/Q57mKejILg.AvmFRk/bLQRyzbnq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51d12802-1ba2-46cb-b392-f7d6ae60d738', 'T012', 'T012', null, '$2a$06$TeqM0rr3G1bCeyNAYpopK.NEmXmBkTSuLGUvDCOBZgK.VRmAdhfAG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51d841e5-209a-47e4-a3a4-69589515f5c8', 'MTM164', 'MTM164', null, '$2a$06$nQYNYZUJZryRzKN9ssZwxuUoWjcUJQmbpWdyRG/dlA2jqqqZVT7DS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51e0eb04-edb3-4700-9c49-6dbab5beee9f', 'SP452', 'SP452', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('51e26763-b54a-4a51-9cf4-24791dfc5dc4', 'TFF085', 'TFF085', null, '$2a$06$/MY1WVCYzLHzdOU/IlbXV.BfPm/8QY7J.yq3ZWy.zr/zzAJOPxb7e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('51e8d7a4-976c-4ba7-be2e-5d80da08d99e', 'SP034', 'SP034', null, '$2a$06$Y3vHwAQDC70l0Qvik5wvae9ERiOYDb6KNHCehegrrCobR9fiSCTau', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5206518d-3f31-4d85-a543-ea9930ec93c3', 'TFF210', 'TFF210', null, '$2a$06$TGGYXATQGBmwn4cZyTUyUu2tytAppkOoYb/4dcYGFnAMwjeQ71HFW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('522f4ce0-510c-453a-abbd-3ec396261ad9', 'TAP194', 'TAP194', 'https://search.google.com/local/writereview?placeid=ChIJrcb_i37rDzkR11-dJslmcWs', '$2a$06$qe1P85M.x39kr0kwKIoxXuSJWL5DJRlcNOqSSN0gt2BjwhdyB.v5W', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:21:18.055207+00'),
  ('523ce24c-5429-406c-b200-ae7f2c68ffd9', 'TAP058', 'TAP058', null, '$2a$06$D9kfcZWfGfa7sgZX8j5Lj.gQw9.e4ZGQHe0olFyBkwGwbewLW0DQG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('524099d6-3894-42fb-b2ac-41c35cde6bf6', 'MTM392', 'MTM392', null, '$2a$06$8kJDPS/btzEROY3TAJ6AZuPQ8FXA3FXrez1B4GSTNOl/Q1u8qe2Pi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5244fc08-4e26-45b2-b6ce-45015890afff', 'MTM378', 'MTM378', null, '$2a$06$YiTau/JQDq0hlORLfgNKauCwmGDiDerXu5CIaXiMgcAARja9wYFzC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('52492a88-c489-4451-81ef-0f3d3c3ae5b1', 'MTM414', 'MTM414', null, '$2a$06$I32yvIc3/g/ZtmYf91Tece3yQAErov6zk/cXMOiICO603yYrqsR9O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('528f76f4-06e3-4c41-9720-2b2fa37bef71', 'SP375', 'SP375', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('5291a462-3a39-4aca-afe3-612f1d892733', 'MTM253', 'MTM253', null, '$2a$06$6Wd9P1IWhCQlKM4FYFhGGOAYl1jrmXD7NayNrCAg1uIV05kpIE5we', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('52d8b099-804e-4224-a4a1-a970f8dff9b9', 'TAP393', 'TAP393', null, '$2a$06$92RgaEbR40cjPAoWj/WXKeTyev/1mjNIp.Y7NAcB8dGVdAZ6RLNoG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('52dc6762-1f6a-4314-a81f-27c47e405716', 'T283', 'T283', null, '$2a$06$IulgssiH5e29KgoUuKxDnODeiOYSHdREwtthPtzYcBDaZLVPsYpo6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('532544de-c1f8-4d52-8cd6-bdfca786beb7', 'TFF295', 'TFF295', null, '$2a$06$o.zWnNzTz8HrSYiHV47WIe.RuKr5fZxH8F67UeWrs6kR6X2QTahaC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('53366d0c-5136-4916-a348-47ea17f229a3', 'MTM397', 'MTM397', null, '$2a$06$3SZSXoSVAWUf5GjVdHpba.TlxukqBegu8ai1X2rF4nRXyvZ7VnB0O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5351010e-e73d-4ce3-b52d-b4d7e20ba86a', 'SP128', 'SP128', null, '$2a$06$kPsdMFZcisDUA6XHsdBYgue3dFqycyBE0CHtmNv20Vj.VP4TdtIYa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5389e318-eccc-4eca-b652-39748278a85c', 'SP048', 'SP048', null, '$2a$06$GxtQuoMDVyT1YDyrfXzZM.NLx9CS7ARxPfitrNp0JLYWp8tr8KFh6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('539bd4e2-cc38-4717-9b46-7b724fa341b0', 'TFF182', 'TFF182', null, '$2a$06$/z1YliIBiKZmUOHOGs1ceu5xVUYoBrD4wv2S3DAIQUGRLWj0QG5LG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('53a62377-48aa-4960-aa26-f74d8a9febb8', 'MTM129', 'MTM129', null, '$2a$06$0v3Sv5dsW2V/SCdN1bywYuCcKIfLMsXO7DRgfDrD1ISPoZV/iG0.2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('53b20054-5d1a-4b9f-a69f-aaa31a2c5ba2', 'TFF319', 'TFF319', null, '$2a$06$.svDurqATRw3VkqBM.xiIuWvdvyXTGp6I.ISc6zC27kvWZPD7ITY2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('53f2325e-24dc-4ace-a522-2dba80cc6092', 'SP411', 'SP411', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('540942ee-1293-4451-8ab2-19b9141b0ac2', 'T138', 'T138', null, '$2a$06$OCnkO5yK.3t2whMkHmdGpulqOyXBq.E9tndMVdHGft.bJuUne3ldm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('541006e2-50bd-47c3-af05-7efeed4a1705', 'TAP261', 'TAP261', null, '$2a$06$FZZgRMwrGELMN/KncuepWeptpJ9zM87PiLdosDxV0DK0orE0THXH6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54176884-ff1d-4bf5-8cc1-d2aa89d2aef5', 'SP243', 'SP243', null, '$2a$06$ppDCYgpKMgTgV48117TYJOV6PmQ9i2jTEN5WoZ680PTl9rrUkYI5W', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('543eccd7-bab8-4fbd-8281-db72474a2017', 'MTM400', 'MTM400', null, '$2a$06$OnwAsukI0rqWfUShGnToyevhxMM9.0bM9.stI6RUOpxNMKmpMbDlm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54480797-6877-4672-8597-f69167c90521', 'TFF005', 'TFF005', null, '$2a$06$X3lUbOlVRUXZ9/XK9y7l9e.aFFUWhpOBjmugZ5wjiIP3Gs7FO6Ao2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('545c133c-5e8d-4e3a-bf4d-df689f646db7', 'TAP372', 'TAP372', 'https://search.google.com/local/writereview?placeid=ChIJPZr6Dprr3TsRGd82bzekSdM', '$2a$06$K6LCpjzIhg/GZzen.bUB8usqkWRS5Dvi3egPn.zX8C4gXDFwxtINy', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 06:44:31.319143+00'),
  ('546087b8-efb2-49e0-b300-42cecf2979f5', 'SP167', 'SP167', null, '$2a$06$CZnc09kC0AkJr9t9TW33t.ESXWGm9YDmgXBcGmlJ/.mtB19AK02.2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5468a225-d38c-4f4c-be8c-4f36e055f560', 'SP263', 'SP263', null, '$2a$06$muVaxgdQixpBV3vYv6ybg.at6isNz.rJYEcG65x0v8o01a5QD7Yqm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54690c3c-0768-4860-9c96-c9d09bed0858', 'T287', 'T287', null, '$2a$06$6SALeN3uYZrD3T5pWVcueey8nxq2P6uy3GKfY2hoOwkqizKGtf7tW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5479e591-cfdd-4d4a-bcd9-e671383ad9c2', 'MTM139', 'MTM139', null, '$2a$06$2LKSM1kQoH72POz7esaReOTkf7tMVBruhVfsMXHT3ztxWgnsq9jjW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('547d1c36-8440-4ddc-a77b-b8ce7a1fa9f3', 'TAP004', 'TAP004', null, '$2a$06$NlNV/DiA2M7RtKzijjpsFOSsmX06Q4V.Eid9f1Pnu4DUECCGwQBX6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54bc5e28-a3bd-455c-86e4-e067f9f9659d', 'MTM280', 'MTM280', null, '$2a$06$EtvrTQjSdjKiGXu9jIEQLO/VwBnOMN.sumevVZT/x9gij4XII8rJK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54c7a369-1212-48a7-b6ea-047659f760be', 'TAP212', 'TAP212', null, '$2a$06$cOpzN0aN34BT.EsoN37.Bu0MEorYax.lxu2ZiiN8RRQSLmtdAe7TC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('54d4e10e-0318-4f28-bb85-7bed0fd60d61', 'T135', 'T135', null, '$2a$06$.O/9OV/TkElUWY49UWbxg.npvsVVZFR7cx5gD6km76ZiZUQdK4OIu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('550d8747-f2ec-4586-ad90-7966b3d4f8ca', 'TAP027', 'TAP027', null, '$2a$06$BVK3NRDTc56VTPfHjox1BufIxqu5M7VcMSP/rCrTvC3Nebln68kJm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('55113fce-f240-4271-a735-15a4a6bece8c', 'SP028', 'SP028', null, '$2a$06$Qwn.hlu2frCsHru.HMXnWuVjYgmdNRZhQ8E3lKIxEISuYYG9TcMPS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('554284a6-017a-4999-9d33-8b52f8e06c2d', 'SP054', 'SP054', null, '$2a$06$FDU6lVI5Js3w1/MY.FWAzuPP3MJ3oJQk/KFuMD.mYB3e1vGeI1802', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5593d330-98e0-428c-bcbd-eadc756c344b', 'T025', 'T025', null, '$2a$06$Lq4slftbMtOWGu1hsMBq7uz5EsLTFZZT5r8QOp.oR9dNljC2/HcKm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('55c53071-beb7-47dc-886c-22ac215fcc00', 'SP219', 'SP219', null, '$2a$06$mf1ZCnQ6wHMvvx9A5gmZOu8emTTzn/l6jTcP2r5RHeaffQH26PeIu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('55d72708-c4f7-41d9-84ce-92f52ddf18b4', 'TFF488', 'TFF488', null, '$2a$06$l8K6WH.ArQ0wNa4Mr/7JaeFPr8UGDHJdoB0r6UL/jAoUQPQdVZgKi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('55d7e8ab-58df-43d0-a702-1bbac01c14b9', 'TFF066', 'TFF066', null, '$2a$06$.Up/VsjHFDS4KzXZPVndbuppALvLfsf3Y2ns64sbAGI6.X7ijRleC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5605fab1-9e06-406f-a1c3-cbd442827bf5', 'T102', 'T102', null, '$2a$06$HorMKVKRCUKYIg1OgNK/EeH1FHTSXp1hr7DwcoF./PioeptGzsKYe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('565ba731-d8b4-4561-b8c2-03d30236688e', 'SP195', 'SP195', null, '$2a$06$l0GU6gJC9iMLQRcWJuM4juXKHux.q3Z8Ets7.dGCbKwzAhB1ZeWzi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('56c5e90e-88b0-421f-8430-ede4b0c5329d', 'SP221', 'SP221', null, '$2a$06$8Oc30UdoZZdoVXHp5xJP2OO6dPA5P2LtKl8zzr0tukt4gG92e/o3O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('56d28e8f-c3ee-4042-9df2-50e5e9862f81', 'SP212', 'SP212', null, '$2a$06$D/HujoEpTFuw4121XduTXu7/O1Ek.Or0VcgUtBijJ967cavAk.Spa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('56d4ddbc-ee6d-486b-b794-9c0746755bb2', 'MTM237', 'MTM237', null, '$2a$06$VhLv7tikmS5CAva1VaZ.T.vjBe5XFCAqlWd2kF6HO6CvviHID.Svi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('56d7423e-a7d9-4226-9a16-7a615602a6c2', 'TFF122', 'TFF122', null, '$2a$06$y5yfXCLVV3jzhdnx/QJ7BOGpN958eQ0osoRg.hvVqoKmcN9Ru5dAq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('570d3171-cbcf-4041-a699-255397fd6683', 'SP106', 'SP106', null, '$2a$06$ZWzwPzowSRK0dz3cS3umUuw8PwnkAfQJ2aw/LI.tXcT7zZBG8OrlO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('572a5b17-2048-443d-a32e-c85c74bd48b6', 'T069', 'T069', null, '$2a$06$UKGucZwC7xj2toj5F2pvPufjTE6UDr3rOt1wBswRyEBx691g8PEai', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('572a60ff-c8f1-42cc-ad13-1f1b6cd9b257', 'SP062', 'SP062', null, '$2a$06$c/O9Dap2Dbpf8fOwNOM/nOh7s/coUm5L.OUx2tfsrXf2qOi1hkcDu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('573bc9cc-6218-417d-94e3-42a3e0ea42ce', 'T027', 'T027', null, '$2a$06$mvfHvQGLpIRWh5ZqzbK.SeYm5kTOIWCq10Z9gNU8rXL.cO36KspXy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('577fc034-ef5c-4577-b04c-d5ebe4be9916', 'SP492', 'SP492', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('578fb784-6d18-48bb-a4dd-83944909e890', 'T230', 'T230', null, '$2a$06$IFOlUJYXokbKvWN73A33Ve.0/8SQv5nbVDpW5BFK7hzDjjB.WLjT.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('579033e8-06fc-4203-bb24-e9fc3cddf900', 'SP020', 'SP020', null, '$2a$06$UcCbfxZ.MUuuLgZxF8BfdeMtngxh45uD271ZIzX25ZHl5rDml1I7.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('57c24b9e-8ee0-4ed4-8360-651838f38520', 'TFF287', 'TFF287', null, '$2a$06$FHyhNLb0vTqX4KVcJ7ydguGPiX8sr.ROoMt.PwtWcCfWV0GFcKDfC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('57d2e5c5-de6a-4049-bba2-5725ecd4ec7d', 'SP126', 'SP126', null, '$2a$06$Wcc3MRM7WuMNtTrGWbPbqO3RPKMuTFfUFGPx3305XewZqBL/mM0qS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('582aad50-8d08-4de9-af57-c1d5c2b4a615', 'TAP056', 'TAP056', null, '$2a$06$GroxoorHS6ycFoemLT5P3ekr29Xfavz0gZiTKWCZYwTXr61KWyydO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('58416107-3b22-4feb-a396-b74084b1e590', 'TFF495', 'TFF495', null, '$2a$06$cG9roIlGrwmaVZkZ/iMtZuY2MOsZ8mRNb31amgoNKasjdonsaImo6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('584f402b-be36-4d68-aaf3-7b8aae684978', 'SP227', 'SP227', null, '$2a$06$T3ulmYZV47/GR2f6Imncb.vw8VUR9UibGGVwWX0s0bcwAgKjjdP4S', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('58817e26-d7f2-40ce-b68c-fd88ba0d0fae', 'T260', 'T260', null, '$2a$06$hwE4.aBTulQUPUFsg1rQ3eTFwP5DkuSqCtwz8/YJVpzFq5bEmwLUi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('58bd7732-2378-47d5-bae0-3bf6d0f2a5ec', 'TAP063', 'TAP063', null, '$2a$06$YvDmt2aO4FkcV/Pearcl5OT1WY3i/Vawuv9x4O08QL8tvVFYymRAi', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('58c3c9bf-f7f7-4ee7-99b2-3dcdfaf58a82', 'TFF280', 'TFF280', null, '$2a$06$hMm7IPfO4FfsY.bo8S5yJe5aKnyEKtHp.iHFUzVwFOyA7UKfYQX6W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('58c472bd-d5fa-4f95-84af-a05093407116', 'SP136', 'SP136', null, '$2a$06$GNJLS3SM4mgfgDbDscvEZufRt.AH45dKdAHEqH7LY8fm8BYjGBwG6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5930862a-b52c-450f-add3-01326e9248e5', 'TFF400', 'TFF400', null, '$2a$06$Z1RNMwG4TQFyyxhDVZCEIusZoU3tWpwbQGERfXIiX4U6/O6sKemZa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('59433cf4-a6e4-481e-9267-5d758c466ca0', 'SP181', 'SP181', null, '$2a$06$oS22vqFUXqHkU7i653Zin.vaRlkFTkvwcziVRQd10ktnSlLgguGYa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('59a7123d-c60a-44b6-a2d4-1cb241ef3bfe', 'TN17', 'TN17', null, '$2a$06$p.LgsV7X17wcv3kR0VFoze59dZHcU4KiHeLz9ZlpZGdzglsKBJQCW', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5a07fe0b-9ec6-4046-a083-5d6405767957', 'TFF487', 'TFF487', null, '$2a$06$UsRY43g7l4wGH7pCFqeQ/O0AOSDUf/ekWJEwiU.wtAOMnf/KqL3NK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5a0c7558-89bd-4bba-8e40-80735b0e7ba2', 'TAP006', 'TAP006', null, '$2a$06$.vUDSPet1Ee0gv6HiirEvOcUvnHxibCPwa72CE..nFYf85udsybXu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5a6a3bf2-d328-44a0-b788-61c74273de3a', 'SP202', 'SP202', null, '$2a$06$7vRi5FFIlWUqVKThuABA2Ow3RcxBdE8bAP87v5NDBe3RQ6Dr8MHTC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5a9200b4-c82b-4a39-ac78-d5beaeb31c0f', 'TFF409', 'TFF409', null, '$2a$06$EB1bDsNNL5ND8y15EO4i8uY1M2vSf61g9eiAJWoA1q/EfAX7ASVve', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5aa3225b-25ca-4db5-8f74-141ae679f6a0', 'T065', 'T065', null, '$2a$06$CSwPu5VI7ArUrV/WC2BEn.5vA402Nyidz634n/rcT4iVP3wV1KP5y', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ab4ab77-8805-4110-814d-220ab2515cc9', 'MTM328', 'MTM328', null, '$2a$06$XkuQDEh0P6KueYynBxCpKO7kF7zerC7ZKfvIVzcgcjdYvj59oaWwK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ab6d500-671a-4856-801e-ffabb54c9201', 'SP080', 'SP080', null, '$2a$06$momp77aXMWNX/PVv1lfNG.ZhjaKS5AqH47wXCvQXzVnpXALJjB7aO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5abcc5b9-8f94-4f39-a3ba-75f6b44ad1d3', 'T022', 'T022', null, '$2a$06$0PxKO/H7x8cj5XW/nM3J.eIyi0I0uVQI2geRm9Q4Oml6KDpUwYv3S', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ac876f8-c99d-4f97-abea-3d95df6f73a4', 'TFF312', 'TFF312', null, '$2a$06$kpP5e5nLpKMDcZEnrDKraOq4pztiua4HYufWkxa5jA5rW22rbU08e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5b552ae8-29ee-4f01-b2b8-45369af4c559', 'TFF429', 'TFF429', null, '$2a$06$V7o8YSKYsZcF3nPSjrF.SONOvS4/EScizEVmqURnLFqQPq1wxmRoa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5b720807-5c41-451c-855d-b71f29db3e3c', 'SP302', 'SP302', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('5b859a2b-9477-43d7-bc6f-0ec6327c9e57', 'TFF348', 'TFF348', null, '$2a$06$3gRc0Rd8xNOh6KmlUNVlx.saqgiovb2V3Q2hu3vHN2FpohN0dIeCm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5b86dc56-f271-45ee-817a-e6836fc0c2d7', 'T221', 'T221', null, '$2a$06$MGrGPixABw9gKDSyKTcvAuz559IhG.WWH9d4aHWtXwn2pc7w1p11K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5b89926d-4e38-47af-af08-d3105775384d', 'MTM268', 'MTM268', null, '$2a$06$bX6w1L1btFO2NxO56tTXQuNCKL2i9hS.fz2eLyVZ0wNDwWx4rbM2G', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5bb5c10c-25b6-4dd2-b96e-8ca471c842ff', 'MTM125', 'MTM125', null, '$2a$06$2Uia848D./d6kf7X3biqM.CQdWh0/WSpwezKJltHvquCrpjSMpiZe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5bc22653-2d30-424c-b792-5cf99ca4a863', 'MTM282', 'MTM282', null, '$2a$06$HAeO/DXMrzwDL5UsZQC3NOVOLPLy6ahw3HzCQqn5Z9/mQHkFUgEPC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c0314c7-dd76-4652-a32f-db460db63f56', 'TFF012', 'TFF012', null, '$2a$06$pYjDGSh4QCXPGFeJjE/Th.RQgHHn9NVFxCIsGNOjJtHnKLgQC3ZoO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c0e2974-5bab-4549-ae4f-05d646b96317', 'TAP093', 'TAP093', null, '$2a$06$nXm8ojQ13N6dYj9NQCPbdOMEUJm4EViXe.X3KRNYvpEnjznAvKfSW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c2e47b7-4c31-47f2-b0c6-511b64d6a95a', 'MTM241', 'MTM241', null, '$2a$06$OD8rLLo4wjXkD39qN26dxuAQGrbZePiTQ7o8Zwsp8uB8iCeAvYaq.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c317fd1-1dcc-4ee2-ae82-1a2e0cba0c5d', 'TFF044', 'TFF044', null, '$2a$06$mNLOtvbkM2ZwiD9M5OIVwuAi0DDlmhawFdLkS93QEaMD0Q0MztuKW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c488291-022d-482f-b21c-5c6cb95abe78', 'MTM303', 'MTM303', null, '$2a$06$zaMVe10Ua6VtecCF4M7axOqMXL6LuOD4jIHENe5lj.csQwiCC01yq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c88a9e8-d333-4cd7-bf87-5ce4dc6105c5', 'TAP142', 'TAP142', null, '$2a$06$21JKYAVr25uu6sXU5m3OVuJKpzAez2.Br7MQynB9OGCxMQ0fMM1oG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5c970a08-4590-4e17-a3a4-8bbe9734ef0a', 'T125', 'T125', null, '$2a$06$haD9Aw6IP5AKP2JEakboBuXOfwUHvQ3yH978nALN6CmZMC1ooC02S', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ca33dc3-1702-4a1c-b5cc-cf1b7cdb0567', 'TFF116', 'TFF116', null, '$2a$06$J5e6cP4sjGjxI3s7OmCwreN/SAlcTvo6NAPfj0uaYSoyeNpfbqYA.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ca675f5-3078-403e-a281-ef58fe450f6f', 'MTM375', 'MTM375', null, '$2a$06$WJa3W9Z./gp1EeYVFuDi/enFV8KYLopfq.AX4/BvhZexuK66xXzye', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5cff4253-32ed-4236-a99e-87940e5ea05c', 'SP145', 'SP145', null, '$2a$06$yEJnRhAh8w3znWVqhUTaeub6ESJcLEtzG5.0Baz0uFZWv4j63yDR2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5d0e6433-a8c6-46c2-9109-82522173cfd9', 'SP190', 'SP190', null, '$2a$06$GP5Q99KG7B3muqaCPcge/O6bsnZ8XcU1IxNqgP878S6uknBZHATnC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5d4a3ec3-f603-4328-afef-c93de3437d74', 'MTM448', 'MTM448', null, '$2a$06$KLJmGSArxyNtNRYK5UbXhuwPNuwzSMFUUTktCLAUhfOqLMmSloVpG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5d5c0937-b3b1-4c30-835b-fea1cbe88560', 'T239', 'T239', null, '$2a$06$urgGZU3IItqfoqe0.GT49O.lbJzO51TK5zx8gzyHWhyQyHfCB5q9C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5dd444c7-2793-4444-9c11-28562c9ef2ab', 'SP268', 'SP268', null, '$2a$06$ZXDoJMzBBAR6.e2kPq1b9.61WZzS4bFM4.pWj/74uYgM3UKwZYcde', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5df765f4-6097-434a-bbe7-a8e49e64c910', 'SP240', 'SP240', null, '$2a$06$zwOQt.BszoTd.WHeReocg.BTLqzlZGhvb7Y5yn/1aq8LwUqkMX2lu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5e2b1b69-3763-4d88-bebe-95b66539dbab', 'T121', 'T121', null, '$2a$06$3g9weFFU6kRWDYnTaIYK2OwD5RS8lCu/T9IgTUELAM1BV6fs1Pq3K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5e484f08-2b09-4474-afc2-e7a9b71e06e7', 'T023', 'T023', null, '$2a$06$6259w4OVyM1p6.UsR.qZRuLzRCpBibdysVIeHwEQ.6uS43y2n4j1S', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5e62e766-5602-43fd-a670-745fb6cdfbb1', 'TAP304', 'TAP304', null, '$2a$06$DO2MUIqVi1hnD5NbMr4v5.DGEV7G/3n2uNpMEgOWiKZk/edlut2Mu', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ea1fc1c-1a62-40e6-a4f3-c473a3fd56c6', 'TAP034', 'TAP034', null, '$2a$06$IKEaH7e.5S6m10d7RrN6Zu1YTs3mqiHhkUSrtoZtqbO4FzViA4ILG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ea9a1dd-b268-41f4-99f2-722f480e9529', 'TAP166', 'TAP166', null, '$2a$06$zLsibSTNNsYHMqbFaZlApecR/1v4Ln6F4HRs2mlj08tqUEhkEAd0W', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ee43bcf-a435-45bc-8b35-d2e128da7bcc', 'SP196', 'SP196', null, '$2a$06$TqW.ETZdnniM1vIrEUZrIulSuOyXgFTP3MxI3PWxfzWvDXkfRETe6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5ee9614a-a974-476c-9bbb-95b0f3778160', 'SP192', 'SP192', null, '$2a$06$jA.mEcvFyzIHuO6Gs4ojlOFg2rdPOmurRLCKgX7KV6HG9Lnb/JeKC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f0d62cf-4ce6-4c13-a2b8-4873cc95fd52', 'TAP333', 'TAP333', null, '$2a$06$9dyfeyHUcTmZrYzIs81bw.dUpWtdt9MlZdmXbbGZnHSWdbV6IKluy', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:22:41.610502+00'),
  ('5f0f0e4b-ada7-4b93-a81f-94528f47c108', 'TAP091', 'TAP091', null, '$2a$06$eIBQKbLypZx.R4S1xr/nOOyT2cgMeuB5tpxxxFWBbafUJvh89qT2i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f1cb759-8bca-4ada-8e72-a5c3bd9f8d6a', 'TFF140', 'TFF140', null, '$2a$06$SwRRPHzTZ7MHjkc8glJXROg.Fj5x6g5GxL.rfLJTxQRRNuX03jYhi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f1d6ae7-4d2e-4c7e-8896-f12ff865fe31', 'SP018', 'SP018', null, '$2a$06$EHd4M8SCqaU7uEWVuP94Ce5Ns4qMV45iJH99TzVC/JYSBWtO3yWHu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f2479ef-2a7d-4bd9-9daf-808e6d4eda4f', 'TFF337', 'TFF337', null, '$2a$06$qyYRxYurMR00BP2t7caB1.d7ySUXUbe0lnzoZDICyGkem2evNQhg.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f2c164f-ada5-4860-949e-e9acd89d4591', 'SP368', 'SP368', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('5f2db3df-2a07-46f2-8229-629dc20466ea', 'MTM227', 'MTM227', null, '$2a$06$J.MWfUr9V24d5D9kUPRsxOV3CiCtzzsDCwa0JlEyh9a2Kn/UW7jvS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f3f3b35-2235-4f65-aef0-4bcc2b234a64', 'TFF088', 'TFF088', null, '$2a$06$Q29d.i0LtC07..6hHyoMzOofTbl03CJcWMiynOPMSJc6wHOv3dIlW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5f7d2666-1dc9-4a8c-9091-9320ed982360', 'TAP317', 'TAP317', null, '$2a$06$.o/mjyhdQhek70kv8HQh2OKNj4WUy506vXZR9ewHpkiVaiSagX9K.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:23:29.098837+00'),
  ('5f9dc196-ddac-4892-b8b2-1aa57c3e3cf4', 'T038', 'T038', null, '$2a$06$U9Z0CT2yN7FOwYfGOe0CnOCNCvI2djhdto27byxUSNU2tbEHyx.d2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5fb26123-d1d9-4d63-926d-f4362b71a8a2', 'SP434', 'SP434', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('5fc1ae45-feb8-474f-bab0-0af4edcbec91', 'TAP325', 'TAP325', null, '$2a$06$zsKj3dV/BGcakvOJYtcZseJkxsYH8yuMBnnronFbniAVSj3cuIYqi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('5fe4cb9f-1178-4c9e-9486-fb9cec6d0a85', 'TAP247', 'TAP247', 'https://search.google.com/local/writereview?placeid=ChIJvVpH6f8HCDsRhTSXW9dMdrw', '$2a$06$fhL1Y9lWTN7SIZ00wfB3tOm.ojOySwp8ikRsl8hg9CmuqWNtc8uDO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 17:12:40.351614+00'),
  ('6055b00a-ab46-4b36-8039-87435dc69d63', 'SP482', 'SP482', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('60720d64-0753-4670-b92c-b9b9844f0630', 'MTM312', 'MTM312', null, '$2a$06$OsXQS7ndMgAtw4dYd.BwvO6fq.LFH2vk94JpxxfgfWkI1Ob6B/WMW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6088d803-08eb-4b96-90e5-231a9c8b6adf', 'TAP089', 'TAP089', null, '$2a$06$Boeaf2iN67yx03vpeAkmT.Ovo0vWIQBN25R5jJzDSxMnB/ARjBfXW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('609873af-2fe1-4f38-a014-d05cbed7505f', 'T087', 'T087', null, '$2a$06$GRavG/jsJr1XPJ2Z/yyaceMMIRserenkQPc8eqJuIlfBufMT6yFxC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6099f620-9283-40e0-a7b3-946166704bb4', 'T155', 'T155', null, '$2a$06$COBkzJ.fPioJenqHygnrP.GvxM8Y2e2RCYXeYAw8viXYYB1t/oXCy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('60e9d154-354d-42d4-8ffa-a4954f3437b3', 'TFF009', 'TFF009', null, '$2a$06$vjXd4R04ftxYmDfQ76aHheG/kQdez77Cc50/ZmlI.4CUpn3p5miJa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('60f5263f-672c-40f3-81bc-dcf833a0a5cd', 'TFF069', 'TFF069', null, '$2a$06$.lSBYxWw87uvkxL0g7SV9OD4G6eIfGkMZK/IM7cwvlQFi2pk5sOI2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('61b25ac6-6ff6-4cf0-88a7-39b170a0bafa', 'TFF258', 'TFF258', null, '$2a$06$JFhGxrsKC37pOFhY3tCUPOZ0IMeiovQVrP2zcB/kpWdgNX0b3vSqW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('61ceb157-05ea-4485-85f2-084716147cf4', 'MTM153', 'MTM153', null, '$2a$06$HITG0zlqQidUFMDsB4BfKOYwgC25c72zMvRzEASFTDUezUH0hVaqy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('61db5521-e161-4b8b-bf4a-6912d4b7dac9', 'SP201', 'SP201', null, '$2a$06$OlT0ptxdcUlo2MS5qrhyteMEgilSFHz9cT9CEp4WMSNC2.N/C1d7C', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('62175beb-9b05-484f-b680-8662e9a2adf6', 'SP253', 'SP253', null, '$2a$06$gSfCs/O30FA88BFCbnNSGuCwH7IilCgHjq5vv.aZnCWg9heZW5A1C', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6227307e-7ab0-467b-8cde-30e9f14ea0bb', 'TAP332', 'TAP332', null, '$2a$06$6927SqImj.Pck8jd5Me7Wuv4rrX490QCLPKVfuT3uGF6Ynfe8ZI/2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('62616289-d445-451a-99cc-acab60e51bd3', 'T288', 'T288', null, '$2a$06$YziEqYHoSU95ViQ0KxeeeOMSgnOrcvYBt1rdVOaBm5ajlYBpZbV6K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6284c561-9763-402c-b3d9-03e59d20c850', 'SP400', 'SP400', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('62d473bf-3d02-4cde-b593-5a7eaaa9ae31', 'MTM423', 'MTM423', null, '$2a$06$YL93slOzaanzur9rnfPxbemERabgiEeu6I9JbuoAJaT9MV8CVZHN6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('62f4b495-a1eb-4a28-8df4-2c8fbb59cc8d', 'T005', 'T005', null, '$2a$06$ilpXFwMcWOpgICiIaheeiekZ1Sc/yk1cH0Mn2bM3BElbUhnQ31w3C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('62f85b3f-dcba-472a-a661-2824775b992c', 'SP156', 'SP156', null, '$2a$06$/sLQ1A7s0QIwkrX6L4jtDOfnhCPsLqRBe5WI74.ocTU4X8CxH/ujC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('62fd34cd-78dc-410b-8d9f-24ef35c93cd6', 'T293', 'T293', null, '$2a$06$FSibqctA4lRFbHzCP9wmHuKD6Oo5jTfwxDb1sTsXsW7TidMFKvsTC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('630c4aad-5cda-4bee-8156-162f4d3bfbac', 'TFF343', 'TFF343', null, '$2a$06$Sc2gPKILXeh2Il3yoDdt8.qYj6g5JtcxZu/afxcbRyhE7adWXNT0e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6316e957-b772-4f70-b500-64772a808957', 'MTM166', 'MTM166', null, '$2a$06$vxb/OllYoRF81u1FVTT6LuGG9hgVqcC5lsqD/wMZOLEM1ShWDXnom', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('632ea88f-183a-4488-aeb0-27bbbf3ed930', 'MTM446', 'MTM446', null, '$2a$06$Mwv7LXZhZUfkc8IYr2ZDSeQCIhVdWqWK9ghFHkiVMxb5bdfnF3pOS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('633da28b-3ee2-48ab-b3ed-829489245a07', 'MTM349', 'MTM349', null, '$2a$06$ADFqRLRqiQxv4npwUQfHH.9ev8JsBlNNN.wZJahavmgXrCHeHxS4u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6347d44b-1a1c-44d9-b730-474afb31cfe8', 'TAP375', 'TAP375', null, '$2a$06$b2wdDCM4RbH6wG30N90cpeIyZNG.b.Ze7FnTew.QcRQOT4gUVxASa', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('63817306-26c6-4345-b087-511ffb8b9461', 'TAP170', 'TAP170', 'https://search.google.com/local/writereview?placeid=ChIJXXwZYV3rDzkRBCLb18O5y0A', '$2a$06$v8ZZTuWOlNp2BpwyWf26DuUIxj0zbVXTEJl1wTgYpaTZYifBxQKXu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:08:32.454423+00'),
  ('63b719be-e899-4c5e-aa64-49f35060e46b', 'MTM286', 'MTM286', null, '$2a$06$1ZveRL9iQWLO6MULjlRxXuBSqtX8JhrUQ8ZC4rHky8WnRPFN9bXfy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('63c369fe-4b25-4ef0-a9c7-010de5271d2f', 'TAP094', 'TAP094', 'https://search.google.com/local/writereview?placeid=ChIJwaLkhAfBwjsRhg4GmaI-0rc', '$2a$06$3gO2LiOVhuvsp3/gZaaqm.ZqqcWP8yoOvovM22tIXSXaWjJmPu.cW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 12:52:28.778646+00'),
  ('63e01aee-b310-4db7-a128-39c0a1363630', 'TFF171', 'TFF171', null, '$2a$06$j2kAiigkGuIgYuO7u6YaAeieFswsCEzeysb8qkqf2yC5dcI8tAMdC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('63eb2f16-8422-4d5f-a19c-cda77a248b49', 'MTM291', 'MTM291', null, '$2a$06$ueN6z7fQ7LvQrJ4hnCVYJuYDV82G8uDy7DVZRYhjggz4ZI5RCZHMe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('64192db4-7306-43bf-b4f6-166f72a13005', 'SP030', 'SP030', null, '$2a$06$9wnEBm6x2s5/VpKdaG2UletmsM4e/oDJoFjsMQSLfWr82ESL4s9h2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('642cb851-8cfc-49a9-adb8-4357fd3cf393', 'TAP255', 'TAP255', null, '$2a$06$ynlNpNnauIXLoOxqWZBte..wMPcXzDcR96eyVYX5zbqpmXs6KxIrW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6455f7a4-e99c-47e2-981d-977f04762d75', 'TAP192', 'TAP192', null, '$2a$06$tlM8rnSj8Y8oUwMYHB.YQes.ac/YeBXsxSR4quolhWfacI3xPu14.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('646d9500-ca07-4b3a-9980-80ca55bf46f8', 'MTM453', 'MTM453', null, '$2a$06$yAo6U/oLViNyn9Xn4QBbn.CDRqgILPdMU8shN3HW3UtnJgIYVTR72', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('64736dea-45ff-4a7b-8b87-b5440c405b57', 'T277', 'T277', null, '$2a$06$7xx6Qlykeegwuc0woneHPOf29eUwkyQGcc27SNvQiPFbVgfSFXmva', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('64b9f028-164d-4675-bb9c-6ce0ad1e0bca', 'TAP331', 'TAP331', null, '$2a$06$Lpex/iWursYAcHgS1EeHE.z8v7K3Fit/gmUF24mQXleWt4IlHYwE6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('64d706a1-1d1c-4b53-b157-d4f7cdf68a84', 'SP367', 'SP367', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('650b3cc4-8180-4a6b-a292-7c28785f0006', 'MTM394', 'MTM394', null, '$2a$06$DAIfFABQmyVtNCTYnZKEm.T64Cvym8ulf0dgMnxeuVbclEwjxQQb6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('659430b8-c5b6-42a7-b731-4f1d6c7c30af', 'SP417', 'SP417', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('65e28e72-1380-450b-9c07-61511757938d', 'SP303', 'SP303', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('660584eb-0b67-4da1-9c5c-c3894f5f1714', 'MTM316', 'MTM316', null, '$2a$06$hjAx4n2OmIjSmenlCENMx.aLv0Ucs2wcl6ST9yWqyLCu6Q3E84wZa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6633214f-f949-4507-9c94-dcb71ce83583', 'TAP123', 'TAP123', 'https://search.google.com/local/writereview?placeid=ChIJM2jnQk_AwjsRw5buIBAcLNk', '$2a$06$ztl75F6.BPZAKnQyVKmQcOH1b7j0l05Zxt9LjO7BDFOIhEEBsEk3m', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:20:32.654282+00'),
  ('663dba01-5b02-44cc-a3aa-f4059a9daabd', 'TFF311', 'TFF311', null, '$2a$06$IRFerFRGkmpz9MBjxN7CwOTp3pFfk8O2Z/iJ.yYIaJeYUU9phveK.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('66860777-0126-488b-b948-c6c504e403e5', 'MTM231', 'MTM231', null, '$2a$06$wH0NqFk6rjGVhTnHAiD93.GMM/Z.8ARok4eM2mWeS320oof6ajfLO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('669c8688-205c-4ee0-a911-c0702903b3a0', 'SP004', 'SP004', null, '$2a$06$pUGXkBBTW9Ho7KR9/ZHy7OxgYhfoP2dS.IRuyBfX2tt83xxeFjjca', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('66ce19d6-82b2-4190-869e-155e9b947372', 'SP084', 'SP084', null, '$2a$06$wAEP5sridU2sz0NxScvyK.PIejCtoTh7SlW9E9Kg3RVLhO3ov790y', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('66ef3fda-0bdc-484f-a6fb-af8969c3f65f', 'SP186', 'SP186', null, '$2a$06$3KmG3sSI7f6y2n5U7psNKecqZ8ey3caH75xYiw2dDbWPfdLLGJo2i', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('672a0a43-f3b7-492c-af29-7853077b1827', 'TFF060', 'TFF060', null, '$2a$06$f5FYt1k0AbJ.BDHFeMFw8O86.cP.W5DEZ1/t0gRmewk5aVccwXMUW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6756ae8e-7dc8-414f-a419-d7b47071a9a1', 'TAP055', 'TAP055', null, '$2a$06$xDYM68CNn4velmjLzI43C.IbK97SddbPM5T6R9Y0iElcPapf23ane', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('67826460-77a3-4ba2-a5a9-1b680c31348f', 'T285', 'T285', null, '$2a$06$0rM9CLjYQXC4uDbupWAiCuiNCzH.lt/.ANcJcQgIgdiIqPI1K9IHy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6786a8af-19e5-4a4f-b5d6-0c9f74d736c8', 'MTM336', 'MTM336', null, '$2a$06$gJu8SUzl6xOVENyoBvm5Q.YQEod33B7GhdFGMrke4wSLVQUjPChU2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('67aad4cb-9118-4374-b5b2-94d84d52c40b', 'TAP244', 'TAP244', 'https://search.google.com/local/writereview?placeid=ChIJXUIXCLT7DzkRY2PwseyAov8', '$2a$06$h4ad1cQK61IEsxvqExNfPuotpz61ZBO/D5BDi9pwR3GOCX3FzlqzS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:12:09.583307+00'),
  ('67e2e57d-68a4-4b26-a9c8-9fc0c90fdec1', 'MTM215', 'MTM215', null, '$2a$06$aWCYu4gi6DkPPiGw28yJdO1hWhIVSdwVQaOkiPi/ptt2vPktnzzdW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('67e317e0-30d9-48f1-b96f-3ba24fec5817', 'SP478', 'SP478', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('67ebbbca-bd82-4eee-b4bd-56b17145f2a2', 'MTM364', 'MTM364', null, '$2a$06$v0O6u0Dc/rL0yNXUwgqTre2pknYGERm9R0zOaTRa3CxohhGB2yB/6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('67eec947-ec7d-4647-8e12-e64543d02ef4', 'T076', 'T076', null, '$2a$06$4KeBeAXBM7Lnu1NCCCbxFe91acll8lUmohZdGmpx/OoTOY4dxJt7m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('68322a6e-808c-453d-9c72-37bcb01a4077', 'SP319', 'SP319', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('68357075-4a28-4849-86a1-b70365caa080', 'TFF126', 'TFF126', null, '$2a$06$qe7LkR0PV9fjmGy81J.daOsbYcMO3mOE7h.TqaEZduq.LVoMVn7iW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6867290b-369c-4d24-bc0d-5a007925c0fc', 'SP023', 'SP023', null, '$2a$06$4stiRI7DwerZo2NIkFm6SO7aIAeUkBtMsVl35c.h6BVZ77uFaPZjC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('68743760-5ce6-4143-a48c-ff5c857e734b', 'T107', 'T107', null, '$2a$06$35PQeqlwg5xfdsCUsSlOMeUwgBUffzKIUkTaC18xP277vfcISmfHi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('68996746-b76b-42fe-9da6-a1bcacdc5492', 'SP483', 'SP483', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('68a50f93-31d3-491d-87f5-110aa7af6df9', 'SP313', 'SP313', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('68c6f2dc-4fb5-4bd3-9ce0-4a96468ec9f7', 'TAP102', 'TAP102', null, '$2a$06$wgDho5lx9dgfIAvUrurt6O24pY2LNfPbLxl8Sy.9wWm.La5xUBWo2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('68db9d00-cd5e-491a-ada8-33a0161baf3e', 'TAP210', 'TAP210', 'https://search.google.com/local/writereview?placeid=ChIJ_fvhvSDrDzkRs4I9b2be_iM', '$2a$06$eL1ERJauNasGjFloNnKXNemQC1KSG9FEyBSzApM8P21G4TEtRjQ.K', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:12:44.708425+00'),
  ('690f1072-3e92-4201-ba07-b6096cf6ec81', 'SP100', 'SP100', null, '$2a$06$y3Om6R3YVqzHV43pdQgKruobv/kHb6sMU/9z34pLaRPlJMQzpBLTW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6938e7d6-35ce-4131-8a66-b4bbb3445a62', 'SP438', 'SP438', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('6951ccdc-4fbd-4e9b-9265-d0bd776a71a5', 'TFF252', 'TFF252', null, '$2a$06$55jgt3ScvweQ2WRWuz2UVe7SsP35l2omxmUDgPU./H69KzBm.Rjre', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6956dd85-07f5-438b-b9dd-71c537d76e38', 'TFF297', 'TFF297', null, '$2a$06$TG6db2a5fYyGxvcwe0SJa.Hs.rBvKmI.sD2qRvWXNajF9axal97HO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('697382dc-13c0-4934-b19b-76546198bae4', 'TN25', 'TN25', null, '$2a$06$DNoXQeLn6mtzBlbq8oS3TuGBPk5esP0WonYbuIbF0CqE599YPkJoO', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('69795f0c-f6bb-4884-8f14-7b1062be366e', 'MTM238', 'MTM238', null, '$2a$06$hlVdjKttDP0yUg7P9/nNvOT.5rQB4ZtOiMWyx2XSnrmMhbA/oay.a', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('699fbfcb-7b3b-4160-95ca-93e885842c6a', 'TFF241', 'TFF241', null, '$2a$06$9O11sUnNzRZ/BiTIlEyKAuw6xRbRO1uMUlbcM9o2OLNANbMPnRWMO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('69a0ddab-2cf5-4807-aba6-58b2eb0f61be', 'SP399', 'SP399', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('69b69d06-42fc-4717-b967-0091a74b603f', 'SP094', 'SP094', null, '$2a$06$vtlwB//xgqudotnaEffUvu2N1NXLDF88KfB8Y6UC/W.Nhv5bzwzCG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('69e882e5-6a7e-405c-af3b-5cd6c9e66a17', 'TFF222', 'TFF222', null, '$2a$06$S1ZXvV1LQsjaXAFpLt0fDO6//EzOOKHsH1VmWia1YXFHTjuN9gtNu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a0ca34d-6aca-4540-a53a-7ab733c3238e', 'SP205', 'SP205', null, '$2a$06$HMXd4A2wc0OYhCLDE8Opm.RdllEwuieSEfqGBq/sj78RUDnJ7cT0O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a23f2b4-e36b-4bc0-922d-2181e9a997bf', 'MTM202', 'MTM202', null, '$2a$06$3lYlyMZ5h3kj3sDWe5SSpODQq.PtOuBEAotzgIdel25hBCXRei0.m', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a395654-d36f-430e-a859-cd800d26db33', 'SP013', 'SP013', null, '$2a$06$0TOF3r/LXXID7l0CDPGrwuTf4tk6axEv/6UFwYkLoEeXihuRp7S.O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a4ea7ab-b8ce-421a-a8b9-e6393c4b259e', 'MTM195', 'MTM195', null, '$2a$06$jvdjhl9/nRghM/7plwYpROLZXfAC0LA0UBM6x9IjNVWFicUn7FRWm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a5cdf00-ff5a-4831-82a4-6da4750909bf', 'MTM141', 'MTM141', null, '$2a$06$d44IwJBxkL8nKOxmW3WBdO8Zlxkj0HN5Yys0HoKigc0cLEVjhHCba', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a7c9808-3a3e-4ad2-a8f4-ded78f449465', 'T209', 'T209', null, '$2a$06$dVRnocXVuUs.qbTgnG63l.nwHLdchvBrrnPzvmv6neW.vpZuTYEyy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a84967f-18a0-451b-88f4-e18d070b71f5', 'T154', 'T154', null, '$2a$06$N9o9BooL8a6.whMK9odUG.Sv4.kPwr.h3DMguZ76jyg/8T5tv8Ysi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6a86fb79-6c39-44a8-bfcb-85a4b885a460', 'TAP290', 'TAP290', null, '$2a$06$zydigLn/bNhIDkFLo.iUr.tO//CkIYFX.xbw4MMYbdk9PkEbMjJg2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6ac4642b-0c13-4994-a5f6-af8842154677', 'MTM220', 'MTM220', null, '$2a$06$tYFv0pO2EeM5lqzgcw5eQO1BT11QPbPbX5IyLm04Yqq8JCizZrSje', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6acb58f7-e354-4d93-be1e-13440ce16001', 'SP012', 'SP012', null, '$2a$06$m1ko4DfoaC0vhwytyP.gIuHmzby54czcdjhcrC0qnARTGKRR41riO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6ae0445a-83f9-466e-bd0d-2c599f35995b', 'TFF176', 'TFF176', null, '$2a$06$Fya22EiIPToDQ4B8IOYi7.R85VkcB7HIw.zLlaiBbmW748SMxLILS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6ae45828-d6d0-4204-a4d0-08d8387f5bfd', 'MTM264', 'MTM264', null, '$2a$06$S67QcCgV.O5FTxJX0JIlC.X/kOabPGjnW9NbfJR5hdaHHXkBZZNO.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b059d02-a144-4940-904a-700b0fe917ab', 'MTM376', 'MTM376', null, '$2a$06$SUlSNjQ65Is58VnYSwopy.HQI8oBxOmKTVyYjePhededEzKRwp7Zu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b12a953-238b-4b73-b7e0-6d2ca4848fea', 'MTM381', 'MTM381', null, '$2a$06$KX0X.1B6UmGoeC4PZpGjyOlKnJ3U5tYuiV8vyvHZHyq6tuyAZGuR.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b5b30f7-915f-4023-9240-375812cb6cba', 'TFF282', 'TFF282', null, '$2a$06$WgopJ7uCNzSImWpPWN0bAuAS5..M7Fp30Twdq7t8XbTQFimscFjkO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b6bccc6-82ff-49f8-9970-05854c468cca', 'MTM174', 'MTM174', null, '$2a$06$IOg8oAUeqIQBx5Hq4DXnJehnPMD4eyAXQoRoWXyqjLkTYH7q3gGxW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b737263-cc10-4e80-8da3-def386587484', 'TAP360', 'TAP360', null, '$2a$06$e9cx/jp53ZUBOcjdhiUhhugt7pHj2yN6IBSJkO19p127RXFdPNzZm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b968cef-a5c8-48fd-9085-79ef9f96cc66', 'TFF382', 'TFF382', null, '$2a$06$S3PmFplAD3Ztbzf9B8Vdw.pXzEyp0pVRcKgVnDb750ngeyLHtpKeC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6b9ba27e-3f40-4aad-a366-2cb4e52f3901', 'T134', 'T134', null, '$2a$06$MHybMwHaqF7Uh1ELrgnYvuy/pSL4TdG8CWnglnAGJV4If2SaluNNG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6ba337bf-466b-4d1c-b513-687e4a67362e', 'TAP348', 'TAP348', null, '$2a$06$Zfmw1loJTHOGXVJnaX9l.OVVEbFFtorAEmyWYfHEPIQqFNN4DOImq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6bc43d37-4b34-434b-8784-6f387ab70ece', 'T295', 'T295', null, '$2a$06$nMlSrCdc5C0JkZbXGJQ/l.LIb0/axiONmCljzJsfKWq5kFB.fK6um', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6c034a79-54bb-4598-ae6c-108c1a81333c', 'TFF466', 'TFF466', null, '$2a$06$rGlD9pkYphRQIYzXc5OQ9.qXmK6ztLyiRAK8g7qNsL4puu0kkj4n6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6c312428-5c2b-4827-9774-d4a7345ff31e', 'SP293', 'SP293', null, '$2a$06$6abtr2PZxtJEk8S1TrSfR.yb3QkXuogjii2KSG3CL0SQLQFVb7xRa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6c4504dc-4c61-47f8-8621-352b9bfd2c53', 'TFF416', 'TFF416', null, '$2a$06$4Ee1EgHmNzM5rQWYEv6FjOIRDtAtcUFVgNomoEv3HnmUKS/XQfLlS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6c4edcf2-da5e-4057-a209-7cc8cdc85b53', 'SP379', 'SP379', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('6c5dbad4-5503-48aa-8a07-9db3c8501749', 'TFF026', 'TFF026', null, '$2a$06$sVmPpepaoaaDxRIHyQ5c.OniOm5R4xhNvPh.ygCw6/gg8F9GcAqp6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6c758b28-c827-46f6-9ac1-65b45a3e9ed6', 'TFF004', 'TFF004', null, '$2a$06$GkWXt1U5UbVV8.X085ze9OO3WykilV6qmHe6NNgaxViX5GCNxat9a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6cb5c915-9a28-4798-bbda-76829667008b', 'SP382', 'SP382', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('6cc2fc2e-523e-49c1-9c6a-63d10b267de4', 'SP392', 'SP392', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('6cd7542c-0e78-4ee2-8896-a41d9c199598', 'MTM194', 'MTM194', null, '$2a$06$415WL357hstTSk2OZwW2ce/2uaGykbw4JLOZ59RmKsMNJqQtGDLz2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6d896394-4e25-42e2-bbfd-ed34456e0b96', 'T167', 'T167', null, '$2a$06$Q8LZ4cXfhJ7B9OJedwUoDOMVWIOy1O4g8LJh1Q8.Z8gN6eNm/PPS6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6dbbbde6-9f96-4b03-bb31-3c815d02a86d', 'T190', 'T190', null, '$2a$06$ljKpWL8VFeAb/wKfCJS9Vu4RtVilFdkaDKrRES145CUcH8FPoxR0C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6dd0fb82-d2d1-4854-8e1a-bf0f9b2957e8', 'TFF071', 'TFF071', null, '$2a$06$AI6qkJFhCWB4tFGVyGEHKu8hkk38q5sToxxpcq/4v21fNDaWHZmaK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6e232184-3b1d-4149-889d-0a69e5f330c2', 'T086', 'T086', null, '$2a$06$3E8XMOCvsAZ1dSoWBKbZqOnhhkZOAYtS5LkD.rNLl05YI8v2OcvLK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6e5018aa-133f-4d6e-996b-0b8b190a3eb1', 'TFF402', 'TFF402', null, '$2a$06$9jXigKYhu9pt3JxxLVwna.YWNSBqCj6gcg9SdnTj2zp1q2EIH3XyO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6e750dfe-5d66-4914-9e1e-b67455dc9632', 'TAP351', 'TAP351', null, '$2a$06$dyBaIZQ5ypiZEGE09ZURDuMRNexJSy9g1kn17.BIlXQggPBYCaWT.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6e78837b-34fb-4a1d-a10d-847f095a3a94', 'TN19', 'TN19', null, '$2a$06$/eLX8H7CH2FS/1pVc2PgJ.2/Rs9flKLpq44UYHpegKua2G29P8W5a', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6e927a5f-f696-467a-af28-53e97c11b9a7', 'T106', 'T106', null, '$2a$06$.ywoUBT82T8eqdKBX7jwceunAKLE2hhMZVfenPktOxgHvqgpEJyzG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6ed4084f-ffa3-474f-bbee-60f10ba0e064', 'TFF092', 'TFF092', null, '$2a$06$M28I6XGKb5y0isB8NJHOy.jPu0js/RJ5wDaB.41kW7R/3/Svoa2sa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6eddb197-1553-41ba-ba3a-3263f328a26e', 'SP077', 'SP077', null, '$2a$06$3Wy69jVv7Efi7dLxA3lp2uTuzYho33/nMWBTq82UImDjfus9UCybK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6f3f8645-ac55-45f4-8679-8ef83644d38f', 'SP450', 'SP450', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('6f77ce24-ad7a-4277-9394-eddece3bfdd9', 'MTM315', 'MTM315', null, '$2a$06$n9IyEgTcrXIbpa54Z/bjL.3or9aSQV2OHcs8CGcD.tJhdNM7Ggaeq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6f7b40b8-54e1-4ebe-b79b-efa6fbc695f8', 'TFF079', 'TFF079', null, '$2a$06$lnSVSWG3/jdd9Wq9GJpKgeMr314H7pzetgY0Kf70njjjRE3WUiQU.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6f7beaff-21d1-488a-a316-e6442a91c655', 'T008', 'T008', null, '$2a$06$1NYTrgmhG6.MvATkBEVc3eP2b097MnC6j5GBtZBlz0/WD.QpnNYXW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('6f81df0f-8968-4f37-b1f5-058ff8d7c13d', 'MTM170', 'MTM170', null, '$2a$06$HMxkCfYeKRoPJ7SzJtAD8eEiHMRYYczplVEVn/GayjuqB10HwSFUC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('70073287-4e7d-4597-b704-a7b661e5c06a', 'T267', 'T267', null, '$2a$06$zVvB5S2Psja9QbAV1TJbT.0I5vAFlU180Qwy4w10rQ3IGJJeXVICi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('700759a5-f051-49a2-86cc-7ceb508452d3', 'TFF491', 'TFF491', null, '$2a$06$y/OQwhS8LWEnfCWR9acu8.c6k0jqyysmOsI2DIp60QTjsrsh/FwrK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('70099edd-0f0a-41f2-8121-cfcc12df4cac', 'TFF350', 'TFF350', null, '$2a$06$nq2FftwPqZ2mst6rDWwKRuIPkWGB.qqxhSACid.y0OaWq/LxKEnu.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('702ef5e4-f5b5-449d-8b06-49847074bf12', 'SP178', 'SP178', null, '$2a$06$T8Ei4aI1dWUP8a6ZVUfDU.c8Wx4Kr7MHyKK3ESPhBBJCgTJXIyVNW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('70638cd2-4ad9-48ad-8f94-b5c52e2f6203', 'SP363', 'SP363', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('70665945-7bfe-45f8-b645-563a9458b0b9', 'TFF393', 'TFF393', null, '$2a$06$.8j6UYZmOQTATVBt3GAFfOFPh8nE2QBgvWlBod28Lw7zGSpuWPfoq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('70bae523-8dbd-4d78-8b37-2e49f0830b7a', 'TFF415', 'TFF415', null, '$2a$06$WnhZDJWf/Wr0zKVlgT0ko.T9DvG1NTw8ijQr2MCks25SNVNwi8tXi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('70d1d9a0-03f7-4689-983d-90cea1bdcd5d', 'SP343', 'SP343', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('70e5c991-fe41-484d-afec-e933be7686ce', 'TFF389', 'TFF389', null, '$2a$06$LnSDiyKMOwyaU1UFPY4LNejFwdJ8yojJ8BgnuYGrJcfZW5X2tHMam', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('71185eab-0b04-42ae-b3d1-6355f9a3bdcb', 'T231', 'T231', null, '$2a$06$c/hAo1I4lY.KhA6GorUWT.VkelTAqlcpzAldR27mXM2zJ6hqeKCk.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('711f11e7-9ecb-495c-afab-0d4a2dad99e5', 'SP092', 'SP092', null, '$2a$06$kOMuJFplkxYn4lSQJO3p.O0AAnQ8xWX9vHw5oKgOUSAZNAZ9UnE/K', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('712b9e12-0766-4e2f-b550-9ed7db5222dc', 'TFF439', 'TFF439', null, '$2a$06$DqZqjcEEBcy0kCl2zpmSGOhFAY9f3BWZQrcmmfFq6kTLvYK3HdRzm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('71800122-a417-4517-9b47-8881113da77e', 'MTM342', 'MTM342', null, '$2a$06$c6fEfdtIGCFP06nwEC4.vORmV82QA0wMPj6n6XNT2WiRL0M47wUF6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('71875aa4-7868-4f9b-a18a-fcaa37618180', 'TFF127', 'TFF127', null, '$2a$06$aq8UP0/1HNBaUEwgpqSx2ujEF4NHIYI78dHBM0quF/xVR2uDcVplm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('71a4d262-e3c1-4423-9345-d4aa6a1fcc2c', 'MTM188', 'MTM188', null, '$2a$06$VdGjvxgr2Sy0LwRgp/kp9.8ZRHavjntJbkou0OaEp4OJVqnW2emNC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('71b61493-a652-4aab-8fa8-c2bafb3e09fe', 'SP305', 'SP305', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('71ebfd43-c276-4bf5-92f9-2d47b8212e44', 'TAP187', 'TAP187', null, '$2a$06$CFjg1DvZw1CSkIVydiCL0u2EJsE.GrQzgVb0UyhSPmqVSUyEP.446', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7248fa2a-b661-4402-835b-1c1c4ab2a92e', 'TFF155', 'TFF155', null, '$2a$06$ti7wsHN4qOzcmMSxgJcqye/c86N9iorgPXftsEQJX7VFiMPsqUVJO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7278e5ab-953a-4f94-a98d-db4356dc248c', 'T200', 'T200', null, '$2a$06$4fzuFXtrcYrGfCuCv/7cDuY2cvyezApxIShqMttFbXvvMvnCYbhau', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('727ce13b-4635-4b7b-a985-b04f4f61c746', 'T013', 'T013', null, '$2a$06$Qr2h52AqWTMgf6n1EOV8ru8hrEYawLuviQL9TiZMKNIrd/FI3HL1G', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('727fe634-f961-4ce9-ba56-092bd30d754f', 'TFF048', 'TFF048', null, '$2a$06$/QUIJUXX.9eE93VoSUlXo.2Fn.lQ/3C.3BTfmIK5eI8xk4RpsuWtS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('728fdc31-8313-4250-b0c3-c76f3c1687e9', 'MTM285', 'MTM285', null, '$2a$06$jFLoo94/fK4RJhVaJ.4v9.4LbdnF0Ys2klNWoFcqOhnBWPEYC20qa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('72a4927e-7910-4f15-9b6f-924999f3dae8', 'SP271', 'SP271', null, '$2a$06$uhnMydXz39PY4v4OeSVMleF9jYURLCQQvkNaxghoaSNhQ4.iuhSOm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('72a87b94-8230-47c7-948e-017ac089643e', 'SP214', 'SP214', null, '$2a$06$7/w9BMh9DdfazhPFmcm7Ie5ddTdVku9KZmgQ9EG.CfsoN4ImKIaEW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('72ae4e79-176b-4756-b34d-f5563413a5af', 'TAP101', 'TAP101', null, '$2a$06$GbmQAi5W1dxn0gf8ZmdTE.tYPPt.y3ULFcxaz6HdP7WSBYMzOLCiK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('72b6ec2b-b183-45eb-a743-732448ee5213', 'TAP275', 'TAP275', null, '$2a$06$3epKdQdP6kJDcr8pp5uzMeat7xj5MoyzHvN5ksoCYA5E9BLWwR.9W', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('72dd5c44-0c5d-432f-be9e-0b29642f6c3b', 'TAP327', 'TAP327', null, '$2a$06$fYkN2YaB94NXmtSD1q3wV.SIUJFLzc4PDa5MvdbYkNu/QlIf7fdP2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73148b51-6199-4166-a0e2-6b0d489c0937', 'SP374', 'SP374', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('73232564-89da-4391-8ef8-ae8e31ff9ff7', 'MTM325', 'MTM325', null, '$2a$06$8DGzEwnuudqUIfLeOk8EN.ZtJ4eAvFRzhrbAP4v8S4mZGKz0IUWdy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7350d90b-2713-4b42-b7d3-a7d7582f4e28', 'TAP241', 'TAP241', 'https://search.google.com/local/writereview?placeid=ChIJrcb_i37rDzkR11-dJslmcWs', '$2a$06$2if9A288VjFNImpzrEQnBOt7av7CPqZcgTcyjPQRjS8v2MBCgRmpK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:20:03.955612+00'),
  ('735cc92a-cc7f-4f8d-8fd8-cc4ce492e85b', 'T084', 'T084', null, '$2a$06$LqVrROOVbF/B6jqY42fvLusyxyo4dtDc5LWzpP9lS0vrQWe6lON.K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73836e77-dd44-4b93-bfe2-8cffd7aae781', 'SP494', 'SP494', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('7392b6ba-fd1c-4fc7-8fe0-42ab5be12cc7', 'TFF454', 'TFF454', null, '$2a$06$PZ/onNKCR3j3ZWZ0jJsM7uMJzl/VE2j8zwsT2znM2hIo3hJoGSHCa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('739f8635-44b7-440c-87d2-654fc19208e1', 'SP490', 'SP490', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('73b09a95-003f-4cbc-9f02-84ecdc33365f', 'T010', 'T010', null, '$2a$06$9684hDyC6NYLBIAAn.KHI.bDc2lZDomP2dSmon8MM/uxbGrmWDPkG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73bed19b-48d9-43c3-9127-b2881bff98e4', 'MTM184', 'MTM184', null, '$2a$06$4CCdmDC4dXvO6L.nSyOSPejaHMfPsuTVd7MW21Wu/4obxXZFVtIwO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73c3c4f8-30cc-411e-801c-7706f91128d8', 'TN02', 'TN02', null, '$2a$06$Nnev/3WOOAqL8de.R5au/uy3Mj1SbAy9hUVYtCuEcLlNv0QSn3SGu', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73ddcd48-b043-4845-8fd1-50f629911c6c', 'T007', 'T007', null, '$2a$06$cHcegy6PvdW/yHo74303J.vvdimLq5m/U4AwKAFEIHbgujBBdcIta', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('73eaebdd-f811-4a79-b5d9-f382536b3474', 'TFF024', 'TFF024', null, '$2a$06$94NJGRsJ8BFdit3ljAkfC.Jts8jx77bZJjGG.15BgEaHPJfKIRKri', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('741bc0da-d4eb-49d7-8951-e813fae348ec', 'TFF035', 'TFF035', null, '$2a$06$HLC5648jubtixyUJjtZ9qevxIu1TvScnU4734G4V6fu9nEpuTTRle', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('74273eaa-7363-4ac0-afd5-9f0cf372f73f', 'MTM425', 'MTM425', null, '$2a$06$aCx7d/QYNE1aS8RWTt0clOtdfn0a6iKN0Lxk1Eou1mlZe1l.fSXvW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('745c32e2-e848-4f77-98f3-7418f1306474', 'SP091', 'SP091', null, '$2a$06$caHPfmgY8aRH3vHWFNm/cOI3YYY3faPAthPUoY1dcjW8AX6nI3..6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('745d339f-d55c-4a17-898a-1816b8ab2b7a', 'MTM252', 'MTM252', null, '$2a$06$WC.N/S8JQio6Zke55JxkIuvRmZODu7JloL.3K1S3eLCsloZztHBou', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('74782a83-8e77-4037-b147-b01a49c1bf6d', 'TFF112', 'TFF112', null, '$2a$06$x0BZBXL9wvZ1T1QjcIS.v.vK9Q4utyO7KOcK5bibYgdS.2W1mztpG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('74bae504-3e70-471e-94f0-793c8148d202', 'TAP031', 'TAP031', null, '$2a$06$09xEYXx1Mrbkh/8h7LzFM.p7Lr21/XpjgcKlI9bTIyo.3v1bNIytC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('74ee9dca-6214-4e5f-8eab-c2f303160efb', 'TFF215', 'TFF215', null, '$2a$06$/bifkunUyPcVmM2SNWm0heUawNcfE7XJiThFZZE5488tME5KBG25.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7516cff4-4151-45d8-92a5-487f8eb54747', 'TAP298', 'TAP298', null, '$2a$06$b9f7qOzD6qb/vi/6hQ5.6.5G5okAwoGQTilyzQKFRBnwYQnwtBQJm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7531e4cd-4bb9-409a-8b45-6c409719a330', 'SP207', 'SP207', null, '$2a$06$sO1nsc9xbXSZs6A25e1FSuNsdlpV9sj5xQDCcoO4yjdf21owcs4Ce', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('755f7673-fe21-47f1-a37c-59b30fc36c14', 'MTM154', 'MTM154', null, '$2a$06$rkGY1gjZfu.Sf.EGOgaO3uqkPbAXdNTP5j/x73V3/IsUVWQexJ71i', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('75b1d31b-abae-4d90-b056-92b0f1a29a0c', 'TAP201', 'TAP201', null, '$2a$06$grpMOinkP7PBuoHErL09u.k.YXg8Orid0dSiShaQXc4Ex9BGILeiW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('75c176b4-077f-4e51-990f-19e6cd28422d', 'TFF479', 'TFF479', null, '$2a$06$abfA8hgL52k6JVXBN4j3KepW/IfUUfbcAfRlYHOj1mxkZ4sNTpbbS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('75eb6a57-eee0-40aa-9060-47296907eee9', 'T153', 'T153', null, '$2a$06$iZkUlBQEP4ZU7JY/iKgtkudgIETquJiG68AsJKnDZKxBcMQILFgDK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('75f7ec52-e9fd-4f11-b8a6-76f47aea01d0', 'SP430', 'SP430', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('768e903b-ec10-47b9-aef7-40dc058fff89', 'SP369', 'SP369', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('769c8f42-2b71-4d77-ae7e-76bf7540d90b', 'MTM266', 'MTM266', null, '$2a$06$jI5h0E5oxL.z/o53MIJ/ouzswaCZobjTZdfmvVJZtx4wuBmDp5hmq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('76b348a2-e2bb-40c6-bd5c-636c055d3ec3', 'SP342', 'SP342', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('76b89ff2-c864-4df9-a3fd-578312c0366b', 'MTM455', 'MTM455', null, '$2a$06$Xm4j5aXFCGbFxIZe9THH4uDilEAE5pMo/GOutCfzIS5SbLgf89g7u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('76d6fad0-4534-4187-abfe-02db20c90b43', 'TAP149', 'TAP149', null, '$2a$06$Vp/MidHmoGLD76id8VOeq.hZiWFvfAC2461SrROMcttwGqUQFSxIa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('76dcc750-f005-4615-b91b-9b44f7e3aa1e', 'TAP199', 'TAP199', null, '$2a$06$P5xONxPjI28Icg2SDf1G4Ox7CFCGP3RwZ1NpI4l7nWFotw.Pm/2dW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('772f11f7-51b1-4b7d-a82f-8721c102994a', 'TAP246', 'TAP246', 'https://search.google.com/local/writereview?placeid=ChIJ1dpJ8xnrDzkRB9bvLgIwRZc', '$2a$06$IlNtcAVryQr5K3RFoSUKhOVMjgHgfkfU76IkqeigeQN3Ogv50AH/O', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:54:24.19032+00'),
  ('7779aa0a-99de-4aec-bc40-d1b705f31ef4', 'TAP349', 'TAP349', null, '$2a$06$2DXPp.ihzMt1ov3XHjvKherj/4DhbIQ45Spg4SSapliVqL6NaE.RO', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('77c1965d-e8b9-48f0-944b-db8960340d9f', 'TFF356', 'TFF356', null, '$2a$06$d.iFJ3yI1wY9I0yAp1EZ.OuuxTbs2zMB4HLq/xZ/k5n7rChV5j7SW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('77dc6c5a-8164-4c3b-b7cb-521488044109', 'TAP107', 'TAP107', null, '$2a$06$qWTBO9Xfat9nrQj3CEGoDeGo/6yuo2.Dh8e3qVtD9c3M1.Se/Q7sG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('77f20d6a-365f-4b7d-b464-100fb231e52e', 'TAP364', 'TAP364', null, '$2a$06$qScYgPJMCVWkJ7QOyV9LDeQcdjkxPwQO9.huhEoHbsjMKebpzN55S', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('77fc76ea-9645-40a4-b1b8-202cc2f5e11d', 'TFF033', 'TFF033', null, '$2a$06$RpyvDT.NQ9qD7MSckChk.uVSdKbi2jsarAsoAlCPlxjOsItX7jvF6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('78146c97-77f3-49e8-81c5-0b630bc348b5', 'TFF438', 'TFF438', null, '$2a$06$6NX7vO47BXj6.EMr1ouX2u80ZDv9qu4wRBJ5or/WAmswCfCfaaro.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('782802c2-2b6f-4b98-9cf5-c2ccf56521d3', 'TFF065', 'TFF065', null, '$2a$06$9kGEXakfoU1qEk6.QLBb/Oeb/Bc5HGfs7MfWCpQtmCqiTNFV0xd32', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('785dfde9-ae13-4c96-8076-030354384a7d', 'SP146', 'SP146', null, '$2a$06$aiUvJmLzk8FPpZT177I42uTh3u7R1ICz7a.2F2G3UahkX6bdkli4K', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('785e3f6e-8a54-46a6-9988-43e2ce0a4ae6', 'TFF231', 'TFF231', null, '$2a$06$7Q.GucOssEKY3B3pggzgJebNxUAC9rdfys.vkJBajg8cCgVqsBuSC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7869fd55-74bf-41c4-bca9-73451fc282dc', 'SP200', 'SP200', null, '$2a$06$JuNDsjfPw2wmhcE6Tlz23.G3hgqYILbhHuhmpMkZoyrGAI7U9j6B2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('78710718-db80-421b-a7ca-2ae847a3fd26', 'SP275', 'SP275', null, '$2a$06$A/cMWcTdspeJM7jSn1h5EepHfh6CTc1OfqLkkFvfhd2aLK5L6OYZa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('78a43d7e-b116-43e3-948b-c96fdba7db43', 'TFF193', 'TFF193', null, '$2a$06$VTAuHQhPrqJdFFv9PzIOW.2aezE7SqSu/azFEvSjmsRq5u7nzm7Je', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('78dc4034-22b6-4fb6-a4a0-f81c97519725', 'TAP245', 'TAP245', 'https://search.google.com/local/writereview?placeid=ChIJGX0Mss7rDzkROjK7hFdiB2M', '$2a$06$HHdQmdfzOtW4aGEMcA0y3O5kKcQ7mwBbNYNlUx1I/X3ra6dgcPGjO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:51:48.915695+00'),
  ('78f0d6af-5d02-4e1c-ac93-86cd4d81152a', 'T001', 'T001', null, '$2a$06$rjMpaFl10x.1/xy8BQ5tVuQpbW.9SiL6diUvgiuMCmQfbET9gihQK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('796f807a-ce82-47e0-b049-0a6ae2583fa7', 'TFF374', 'TFF374', null, '$2a$06$3hACTOqwwPCDSvM4D4HUO.TTImz1ogQBnvTBYi0JIydG7sj2KE8Ha', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7970e612-20ca-4108-84fa-7c6d9d61c06c', 'SP264', 'SP264', null, '$2a$06$cJ.X9XkmScwUY2q0YGxweu/4ySggV2MJOG8zVM8BuTafyJJ9S0mu6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('79c80732-fd96-4150-b374-4b44f8c4a076', 'TAP127', 'TAP127', 'https://search.google.com/local/writereview?placeid=ChIJqTykk33t3TsRuTekAP6oeEQ', '$2a$06$AR7rRJe4yCZKFiHBH0bWfu56HzmnT9EpDIi8qGNWcNFyOyIuCGFbq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 17:29:41.813478+00'),
  ('7a2da5f6-ce93-42a8-9a88-c2c23c459698', 'MTM428', 'MTM428', null, '$2a$06$H.Tpu/v4cMvPWNMA4B/T7.sHURKrDwaOtmUCGD7ydVgEPE16SYhGS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7a48166d-46d1-455f-a2cc-2db66febc3aa', 'SP026', 'SP026', null, '$2a$06$IGqt.lOPjS3.nr7/RW9C9OSt6jcKqugpvaWN/0qHF4.DYgEDkb7Se', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7aa41d57-7330-4f20-aede-5d5aa05c97ae', 'TFF398', 'TFF398', null, '$2a$06$vJHDT/PSwlZc5z6FECaXXethWpqPxy7Jb/ScIbO..G0GlP.U9N8DK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ae448d1-cb01-4119-9aee-e6ddf9b7be02', 'SP172', 'SP172', null, '$2a$06$m3joPpYs5q5yDMKIqzFx3.E55url4WLQIkmD22zib/sCJbiE3rRhi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7b0531ca-fe48-4473-8bc1-7808cf6ed4ae', 'T097', 'T097', null, '$2a$06$7xgbuxOqu0mspglTZ.witu/KmXGJjo8to99eRcoNHO.zv9tCdB3ny', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7b3e96bc-255a-4ab5-9def-be3457d7c470', 'TF09', 'TF09', null, '$2a$06$KdpNIaQGaOWUBoY2Y12qKutXK.eC.5Lw/pZguETVcOR1rzbF4M.Wq', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7b501372-359f-45af-9d05-4650034edbd5', 'SP267', 'SP267', null, '$2a$06$0oJVIvTjgFMkG3wmUJw7EODz7nxwv/i.EnWjkKZZ9BXi7ebs9V0qS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7b5fa42b-3a1b-474f-84e3-b8b406330edc', 'MTM276', 'MTM276', null, '$2a$06$uGe11/P74m0ZnvM1GQdw4Oe8CGSUGVxONd9l/9tVENaap1vt9Ssiu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7b669fbd-3158-42b7-8f06-199a4dfb02e1', 'MTM269', 'MTM269', null, '$2a$06$Hg1AUcz3Oakzdgl.SWzIBOZiPVrAu.mhsYnHk.4cYALYwmMWK8VSW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ba6f0f5-9e4d-4c55-85de-1718d9583e69', 'T092', 'T092', null, '$2a$06$Z91Ya1JOYO/FmNeDagKmReTQ0grxhSLewjIOMjDR8wfmRKWDPyvcy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7be61214-5f46-4306-8c45-ee5bebb8a6e3', 'MTM360', 'MTM360', null, '$2a$06$Yd5qDj6gxeSEa80Uk6JKSuOY7/tEmy0FR3K9yPDKttu2bBzpxB7N2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7bf60494-73b5-476d-9297-71b47d13723e', 'TFF081', 'TFF081', null, '$2a$06$DWgIa42HiscEEQehhZBlYuwunsHN4grMEifVoWNsVvcsTsVuBNb82', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7bf65306-c3fd-47c9-9c56-afbfed2d1c0a', 'MTM369', 'MTM369', null, '$2a$06$4icYoXOYnXQPMFhcpxnFmODxcitoH6XWRYfq91BZkkb1wdcqwjDhG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7c21dd60-bf42-466c-a2b8-08c115d457d1', 'TFF411', 'TFF411', null, '$2a$06$zuhKZFK0p/3KgoySTGSmD.ux72AszNhLOgKjSTh98f8veNn0pjYCu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7c42c363-3a08-46b0-b733-ab6516f27c9c', 'SP239', 'SP239', null, '$2a$06$t4R7yQ.KU1G3uC83SyJVX.Arm65X7hwbXmWPrTq7AbQ5qEWYFzfkG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7c594962-c54c-4722-8ebc-29d51bb6f048', 'T280', 'T280', null, '$2a$06$NT9GkTjzi7GNISxiVzYv6.DMdA6Ll3aGZt27T50TsR3oC1Yx/Rn4m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7c5975d8-b1e1-4170-845b-dcb11eca4c6f', 'T129', 'T129', null, '$2a$06$1KuibmAllDUc7q8P9AmPheDoP/J1QBxVemqwzHwaV1sYP2NWvG55.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7c73132e-5e7e-4a03-b08c-af8db50c8535', 'SP006', 'SP006', 'https://maps.app.goo.gl/rGW75AaxmupPERwbA?g_st=ac', '$2a$06$KJnP8O01S3LtuUbTLl5DVuPcYd7OTvaxfWfhPt3HR7YF/qLWO1eJG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-13 07:01:01.71828+00'),
  ('7cc97a63-b9dd-47f4-83c1-c9917735bac7', 'T166', 'T166', null, '$2a$06$orzWsZK4S5kkI0fY2n/q7.crQebutG06UQ9jeDj/rF3kJ2J91HnAa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7cff1c84-ee8e-439f-9027-c506ec6c1398', 'TN14', 'TN14', null, '$2a$06$u1vhZuuAhBmU/1P6iYc9DuAC/Aceu/dlEi0c8NiawEjChTLfWcO5m', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7d10b4b8-0de9-48ca-9ed7-b39a318d58c5', 'T186', 'T186', null, '$2a$06$TS1MqPIwdliEz8S.JzfRuuZgLBAEvtgwVbZAHLijPaKFqKc0FRxBm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7d27df2e-05da-4426-8982-c855a7c2dda4', 'SP208', 'SP208', null, '$2a$06$JMFOz134RM9ZOuxL/q2uEeSQN4zzxNwOFv8mpd6ljN/1LceIW9BWq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7d3c088b-511c-4415-8394-de920ddc0d42', 'TAP064', 'TAP064', null, '$2a$06$UEeeBO.H5c.NdGexuJozG.pFEAh9mzRliPLNI7VMxB6yd1KoBls0G', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ddcf284-4285-4bdd-8a42-06787eb189f2', 'TN08', 'TN08', null, '$2a$06$FP1spB1UZSboNj7jUJPsL.g2Dd9eli9WYPNM.esXTKWTqXzKo5uGG', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7de35b69-6aa0-449e-a63e-930fe3b71059', 'TFF363', 'TFF363', null, '$2a$06$3Sm.9hOJUc09XWbJiqwLDOvJOHnAT0iyDMLkpiNive0pECLHCpRFu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7de943a7-5aab-4445-ab75-1401884c91ab', 'SP191', 'SP191', null, '$2a$06$nec4djXM20jMLjvresB9v.CreshAHQhWagsT/QrzEH/WzVWJUSXMy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7deccdca-ee2b-4c3a-81f5-a48b3fa35076', 'MTM204', 'MTM204', null, '$2a$06$HDqUG4WdqQu3BvcMtscwYOUEETogtvuQjEVxzK3oF1gqHte3QXw4a', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7e27b4a3-f395-4dd6-90bc-f544cd5154b2', 'TAP109', 'TAP109', null, '$2a$06$VGtZxXXAl29FyMlB1Fz85.MzaN1SHwsgCAlZQfoc7x9UTGoSa3wda', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7e342b52-12ee-4fff-8511-15eddf52cff9', 'TAP070', 'TAP070', 'https://search.google.com/local/writereview?placeid=ChIJ-VLgOX7qwjsRaNvY2gFbHOc', '$2a$06$KZvhMWJGJ02wZGrGHVZNTej.p3yP/r8bi0tpZ4QHqrPPG6BFchphe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 08:48:50.238457+00'),
  ('7e3b16ee-ba8d-4d4a-a3e2-7d714832e740', 'SP063', 'SP063', null, '$2a$06$ltVOE3HrNc4rf7CRpD8OM.3kdmtQoaPfWvunLqNKcGxGuD1OLGHqS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7e4c9980-3736-4544-be20-4bb96b8ae303', 'TFF436', 'TFF436', null, '$2a$06$4dnGG9sAevWp6fyzVqsLFu2CxmEO6fv.amhnR0uZHKfeNH35yFDFC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('7e54269b-695c-4b53-a684-1c3484df8c72', 'SP117', 'SP117', null, '$2a$06$p0b1btgPpeem9.x5IG2D2.awGGz5w14XsOft2a4CT8DG4Zo.KwZtu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7e997d9b-c49c-4766-9c5e-463fd34744c7', 'SP279', 'SP279', null, '$2a$06$F9kZgv2a3mkXCHCiRgwiNu9yRjlfDFTDVGB2TtSLd7Ce8sojuL8Oi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ea575b1-d955-4bfd-97af-2fb6dc59e54b', 'T095', 'T095', null, '$2a$06$PnGYd4tgsMPyNgrMWpdQa.b6AYtt/So7.qZhl7bNjSb2ZYm6a/0EC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ef17e36-5e90-4be9-8e24-0eb922b817fc', 'TFF378', 'TFF378', null, '$2a$06$YkaXUNr/6Qk3JYyVfvC5WOpKzCgQJg.2nGBGA1fn4guG9cSBdPQ9i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f05b213-e087-490d-a943-a892919bd333', 'TFF452', 'TFF452', null, '$2a$06$5oUDo03lfvD.Q142ZbXm9euwTRQr6Jk62uNhxbJQkPv0TtkLMcA4G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f0ea31f-779a-4b43-8650-14c50121662f', 'MTM175', 'MTM175', null, '$2a$06$M6ikKHqoEPWAwsaeTVqbyufLIgr/ljTeTXBPIzeZJEY7uQQCKlKhG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f107f58-7865-455b-a28d-3597b44c648d', 'SP397', 'SP397', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('7f3ca09a-1742-4408-8036-0dbb2d32a1cc', 'SP255', 'SP255', null, '$2a$06$yAZIJp2ccohMP/VfXjd/8OUUXnZEkH6Yb9PnVQtypHe/uO.gkFEDu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f52ebc4-d80f-4cf3-ac40-5cb8495841ea', 'TAP390', 'TAP390', null, '$2a$06$9rRFJvbKzWlI/oyr3eU/WuQq2HMsgq.XJVS.AG0ynVmZ7reRcFR2a', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f831dae-ae2c-4baa-afb4-752165a7fc5a', 'SP249', 'SP249', null, '$2a$06$ZgcxN.q/cQcw2D0vsdaWpujOBxFe5Q.4QXAxE3FwTUA9VWj.msUau', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7f84643b-91cb-4ba2-892a-eee51adcc740', 'TFF076', 'TFF076', null, '$2a$06$NCm2.dPJpaanb0hI2ajhH.Z0bjWXDyfDqTFNc4iuXGE9yK07DE/Ci', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7fc0a485-66b3-4cb6-95e6-afb253fc2cbb', 'MTM255', 'MTM255', null, '$2a$06$rTQe6uOmLWFfXTikdEW8rug5WQlHYCu85o5XM9g38hA4vM/Exrxui', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7fd1f4db-68b2-4884-ad2c-2323072d98ee', 'MTM437', 'MTM437', null, '$2a$06$B/4IjaBytSQdcgITWjZxpu2Olw0fMmKFkuSZ4ckY7PJMVCzpdSanu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7fe5de82-2db9-4dce-8a09-bfb592c913e7', 'TFF485', 'TFF485', null, '$2a$06$wKzIcJk./VyU5GPp2n6KDOCCoqmQDoVrfHMdKUcVaKWk4iXazC1bu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('7ffd11fe-449c-4c5c-b3a6-4f0900ee12a6', 'TFF473', 'TFF473', null, '$2a$06$GTsinSkgDhvz8oQsqYDGXeqRRzzc9JnxVZEMP3/fJWUPAL0ubzova', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('801f9b69-6c2d-4d17-8c5b-2c56edb43469', 'T184', 'T184', null, '$2a$06$1.YbtmvyALIGGBPVn/xet.FgLSsVqQzH/dNdKzsLsnAM7zUqIsGtm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8023cf09-6744-41c2-84f4-0879c48f2939', 'T270', 'T270', null, '$2a$06$Z1XDqwexiZEumQEccSnAfOJIU05scn1pEB/bYy3DqOYSPuPhOI0Je', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('809c6593-1c6b-40ba-96d0-31d2a4b8dab4', 'TFF178', 'TFF178', null, '$2a$06$oAKRo5r0Vkg60C8OARVve.8okUILbd1EurkLrc73fT6mw9.k3ztMK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('80ce60ba-2706-4c29-8959-54aad29e6f3f', 'TAP193', 'TAP193', 'https://search.google.com/local/writereview?placeid=ChIJr3LLMR_rDzkR9tUN7-h6LFQ', '$2a$06$5akC8TkoBGsgTl1mfcaXS.JJN0JE8inuKC.JpWJOHj4h1lIN8NIEa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:56:01.449377+00'),
  ('80d78507-8bb9-4593-ad48-b451e607543c', 'TAP134', 'TAP134', 'https://search.google.com/local/writereview?placeid=ChIJc0L8mgKxpzsRkazym7WM9b0', '$2a$06$0Yv95jE22NfL0H/LVK8fHe/jKUOO/Bc5JVQskXdtdFa.3Re72r26q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:38:08.847226+00'),
  ('80f2a3eb-14fc-4204-82bf-7a2b21c970e5', 'TFF275', 'TFF275', null, '$2a$06$v7Mb31fmFxFcdvrnm966DOgkDUvrs.qoL7K4FsQNwk0PJkHeRdoRe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8151204f-0372-4076-b593-6bae00464344', 'MTM373', 'MTM373', null, '$2a$06$00kYXRppvesdY7BTNpQTDeYKb17a6F7Sn1muEP0.Gjt2GcYq2nDNK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8153bb93-fdd8-47ef-8692-bc2f9bb40ff0', 'TFF173', 'TFF173', null, '$2a$06$uZT9pCJT0Ps69KHGccEuRuQoTwHhJPGqwiQSAbAXw89EJe7482s5u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('81728ab7-bf22-4479-8ac5-74b1d75c298b', 'SP059', 'SP059', null, '$2a$06$78iAIP0EryW0bC9xSAEZH.gXR3T7RRZHNST23zNYNu7AnJ1GlcATS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('818347ce-1e6d-4532-9cc2-ddc124cef042', 'TFF347', 'TFF347', null, '$2a$06$TgPAt.yG5hWjpRREwqsXR.haXuEwwdsZIzXOcjJT7ThXcsdRE9zOO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8195b3b6-da68-4b0c-9cd1-47d08c2b7aa5', 'TFF459', 'TFF459', null, '$2a$06$Oz6XgsHC5gpH3jSFX0Qa2eeCvV2qH41oQKoYqeW660gE1Gs2XKtHu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('81c0fbd0-14fa-4956-a2d1-469254bb5e1e', 'MTM159', 'MTM159', null, '$2a$06$jZP6FTyBz45FDON54XOahuMOFy2kO9VRz2JDpDmqla1NjFiYsKnUm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('81ed84ef-5014-4fa7-b1bf-e796af92ccf0', 'SP150', 'SP150', null, '$2a$06$oBucj2rhyf.tm2z5Tcfyt.jRaEfTXXvPX3EchIC4MfPqT1SooZdY.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('81f0846f-7be4-486c-90d5-ae5a08ffbbc5', 'SP285', 'SP285', null, '$2a$06$nprszQKQIlqxSrmBrdMBe.IQThu0Dh4ogD1aUvcKzTD/TWbYzZjR6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('81f47308-55f2-4fe1-8537-a8126255755f', 'TAP205', 'TAP205', 'https://search.google.com/local/writereview?placeid=ChIJSYWjNt3rDzkRdDgj_4crLSM', '$2a$06$m3CR7BHrqjdDf55gsD/jFOyE6vxfBcUXMz/8dmIsRxvU8iLN7Ho3u', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:45:36.742454+00'),
  ('827d17b3-59df-42e4-b262-fcfee6be8592', 'MTM185', 'MTM185', null, '$2a$06$oYNnh5vUkLidhkJaRLs0ru0X5ml7EpYzt7NqDj03fTg3RtkYXXsNW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('82be981d-d166-4026-abb8-114e7be4937d', 'TAP314', 'TAP314', null, '$2a$06$mFxjLQw1zGA9DhAZXvn6H.WFh4VAgIuYV2hsBAP4BOT5gXZOnhjbi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('82e0a553-5dfc-4d6f-a8dd-623877840995', 'TFF256', 'TFF256', null, '$2a$06$2UREKDunTRzrcOQHf.9A3enoS94zP7gvQvAMTJFxPnoFVnA4xmd0K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('830d3d60-d30c-4f87-ac9c-c96f1eff742b', 'TFF206', 'TFF206', null, '$2a$06$Ct4ieB7AsHgxHuQkSE9Iy.i4p0RZc4FTIDw/co9qPrlbbEMUx8uzK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('83255a38-aeca-4b3c-a982-65a0c0085d9e', 'MTM377', 'MTM377', null, '$2a$06$kkWpAhJNPf6fJ5HfhyKyZulVSSvti9NYajUEJlD1LeaxDL83x.Uki', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('83570281-c658-4cbe-9d54-4f9707e16cac', 'SP096', 'SP096', null, '$2a$06$c7HdB/7yvBoIM4U1DV0AaeYnzRkD/SsanOUHcpHLgD9nZ2AHps6C6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('83edef2f-9acb-4775-8c99-857a69dcb426', 'SP462', 'SP462', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('83f77415-2ffb-4117-b6e9-85f4e2714cd4', 'SP383', 'SP383', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('840a6150-f9a1-4eda-a5a3-e75f8834d783', 'MTM225', 'MTM225', null, '$2a$06$fbnJaAlJK7WUFf8druHWbuxSsY4oaM6S8wNUn73SDwDyoRjAFS1Ge', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('842cbbf1-2c3d-4161-b3d2-7382aa91943b', 'TAP283', 'TAP283', null, '$2a$06$k/mLm5Eh3vtCafg6d8f6au8uSgEicrdiaDwM5OqxkgLUfLXyODQL2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('84413014-a5b5-4416-8ac5-66d80242bbc4', 'TAP347', 'TAP347', null, '$2a$06$gOYq7v5wGXl8iUToWC.G0.msWNml1BWGDA1sz7dEwvEEK2MjBk7W6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('84428f13-640b-48d5-a367-a49c10c4d1e8', 'SP456', 'SP456', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('844794cd-8982-48b8-b4ec-0ed499ba4200', 'T212', 'T212', null, '$2a$06$7N4a4qmmSX1uii1cJbs1au5VHIbp5UXs79uYgGrS00J0EJIqccF/.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('844f6a5a-3930-4917-aa04-d55deefa7734', 'TN13', 'TN13', null, '$2a$06$Z1vEfSEmMqlJ3vibBlWts.BZAVZLqqJZ3PJM297NWGiQj1NjO.dN2', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8458060a-91d4-49af-a8d7-70b24be7b559', 'TFF190', 'TFF190', null, '$2a$06$.KKHB7L5e8b/SzfEsO0EUOkBbyYMc4kuMa0wyPe2H7Uatx/H2rzsq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('847b8e65-b319-4238-910e-e40128d90755', 'SP332', 'SP332', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8482b622-7aa1-463b-baa3-255708f47574', 'SP357', 'SP357', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('84858657-5cd7-4f39-9b56-5d637fd96e17', 'MTM186', 'MTM186', null, '$2a$06$59Y.WRhICZFBmuOjNZhj1uVlhrMJeevSntpdbqpBoG4QgVJetn7Uy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('849ad245-b0c5-486a-b7af-6d8c0dae0185', 'SP419', 'SP419', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('84a8e859-5a3e-4cdb-8cb9-ec8eacba6312', 'TFF497', 'TFF497', null, '$2a$06$XDMkZ9vj0cNGMXqTCLVtKOVr7lm0ibNb28qU0S6l36MeXWXihkUHa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('84af17da-d550-4dbe-950f-eeb1b1807516', 'TFF277', 'TFF277', null, '$2a$06$wnwafhOKawKaSXOV6jcVYOYiTn4wATmMU4nP11c5l3YAwd7GapkE6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('84c00091-c4e0-48b1-b2af-6831ba11f9ed', 'SP335', 'SP335', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('84ea520a-cfd0-4e94-aa6b-4b08648bb543', 'TAP033', 'TAP033', null, '$2a$06$ZpCEI.SASEwbbzqVh8.n2.Y38AgUiV4ILiZDKJlniKiEBpcYJMBs2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8534cba3-89ea-4917-8a70-8d12a221c26f', 'SP405', 'SP405', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('853713b0-a7ed-4e5f-b2b0-3f8e860bfdb9', 'T026', 'T026', null, '$2a$06$w5FAy/H3zk/gQRrrXEjSEO4iml1Y9bqYm5MMQ991m4XAzND8XnVCa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('857ce55c-91df-44be-967b-9e121019ac4f', 'SP322', 'SP322', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('85bde7cc-6bcc-433a-aaf5-01f459d40db9', 'SP327', 'SP327', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('85dd37fa-186b-46ca-8fd2-319b821224d8', 'TFF183', 'TFF183', null, '$2a$06$DsYclaa2TMdWYMHKxS3QBOIztKAbdJD3z/kzlcIMKRO40jWD3t3Fy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('85ff2aae-3b96-4be5-9eab-7305de2d5e84', 'MTM239', 'MTM239', null, '$2a$06$fR7XkYrKSm7WXj/g1glA5eizORLhDiAH0h0h2/kEO3.pZ8YW2nTX2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8625b248-a5b1-40df-ae8c-e5f2cadcbb68', 'TFF401', 'TFF401', null, '$2a$06$KsLOLIoOoTlwM0IdJQyVZ.cxRsjin2mllHFFyNs0/vkfdhgLs.MBa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('86314895-c2c8-49ac-854e-fae218d4a4a3', 'MTM262', 'MTM262', null, '$2a$06$AnxvAivsy9Yvb59qGguhPe2Gn74EBE8FVfbOOMC0L8ZJ/Vo6pq3KW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8637c8c0-c196-48c1-9c65-90dbe712582d', 'SP154', 'SP154', null, '$2a$06$e5JX5y262y4tQxet/6mTKOEpRs/TvO03XcbJgIjtadKmmkJjspKly', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('86689630-7446-46bd-bd9a-3c99b28ff408', 'MTM368', 'MTM368', null, '$2a$06$RVQAF9Otp946pzMjzGCy/O6QIxZKtPsAn4bx5Gr3.7j1fQ8hisETe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('86f3b219-2d1a-4c0d-a08d-3a8d59432a71', 'MTM217', 'MTM217', null, '$2a$06$DaykAuIbi1M2qDbz.v0UouWC92KhNRYtiEdsMKTxtgjZqmrZtjwG6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('86faa01c-85fa-495c-ae73-2140b2eb284e', 'SP323', 'SP323', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8736000d-865f-4442-8487-a65715ee5ea0', 'MTM317', 'MTM317', null, '$2a$06$VwU41tlxRiD/m.xNQXaf.eYyRn9awdC0qXBbvMedkbIV8fjMqBTmu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8763a63a-bba4-4eed-a105-a3259e1f07d9', 'T136', 'T136', null, '$2a$06$1qN5haRf4lwB5ynC7FF4IOH0rz1J9F.ydwRmWB6hDphuzwMqSLqEO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8783866c-7bb3-49c8-8ad2-82c33581b977', 'TFF484', 'TFF484', null, '$2a$06$XIpxl6kvCq1tQTTXsRqzpewwRDsbG23Pzj0GzkIhFJiCbxbPN/sv6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87af1edf-9d2d-4179-926c-f2447b69314a', 'T079', 'T079', null, '$2a$06$GzajBHT5K9sucR59FIiJf.kvr.m9.h0/a/FwFjv49GZOk1aAS1w5C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87be4704-7d0f-4c56-b9e7-4982e1c85000', 'TFF425', 'TFF425', null, '$2a$06$6PK1Uv31.wgNzvc9EC3di.Ve8XX9RWH9Beg8p1lzUn337TWflySXO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87ca1458-b967-4bbc-9e72-e362353f54c2', 'T031', 'T031', null, '$2a$06$nvcnmj1sgnJnEmsA5zYol.Nejnxwt6KCg5l6WkkOv7YHRUgmUEOvO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87df804a-df1d-4e38-ae59-08ae4f966ef7', 'T228', 'T228', null, '$2a$06$jpUuTzgSjcnvldtPN/7XreG9Im4qqfN8s5.etr/RXQoQdhqXXuXpe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87f27c87-15af-4961-ade0-b52fc59a3e34', 'TFF007', 'TFF007', null, '$2a$06$YDlvAyvs/uD.4lTGI7zo5u5l3LAFImQDooLtTkRzMzdxu4K/IuKhy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('87f7d7d4-10cd-4f46-b7cf-d6ef56b94586', 'TAP305', 'TAP305', null, '$2a$06$8LRTyxsxY.WTC.dNfQefHedvUSWsDBLkTkt0b291Y3SGlYVrdmn26', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8844ddee-6731-4271-bf2f-5ecad7afe364', 'SP299', 'SP299', null, '$2a$06$qC6SIIX/dAWPTha9g91Lb.o3NtoXa37WyGbFwvjO5nasJ7Oe.gIP.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('88b27482-a7e8-4591-b5ae-c5afa961241e', 'TFF492', 'TFF492', null, '$2a$06$7cf.NhVjTK3av22k57FQ2.SlPDPI8vN9Da1/UyubgsQGx9HSlQaHm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('88bcee51-897d-4030-bc72-847c80bd18e6', 'TFF286', 'TFF286', null, '$2a$06$eQamaoD1t5lEvNusu.CaneMfkRlc/ytOxddv/IoWDb0x9Pi5Y.Wha', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('88cffa90-bc4b-483b-8bf7-e6b1bf5414a8', 'TFF328', 'TFF328', null, '$2a$06$xecx33ZZNjazOY1otbloReS3z6tp8EvBpmdmn3dKg8TE7KpYkvz3m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('88f2add7-2496-4f62-a9fe-9229adaa4033', 'T146', 'T146', null, '$2a$06$u7UIJqB9sqUc.JAXfkdrou7ZXyvSnxbTRSerhLreDpCeXjjXQsM72', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('88faa754-ef77-43e2-86d5-d28b5931808e', 'T301', 'T301', null, '$2a$06$QbD2QvY7QrROT5wZdaBRQOPS2qWYVZ8LRV/nvxoHVlB1TZXPzqa9G', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('893eec83-1ebc-4402-9138-a204af7db1ca', 'MTM214', 'MTM214', null, '$2a$06$KhYItZv8rjjA.0f2o3MLUua2S1llQmxm8Zl4ANIIIQPT3UywF9h6u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('896d3255-374a-49c7-99d7-930302d1d130', 'SP119', 'SP119', null, '$2a$06$qdx80xwfB.SddNyNI2SZAuI6Lt86Pj1Q6xP6I3s64y3mFzhr2B6Fy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('898fc627-b79d-496e-bb75-2c69016f4f6b', 'MTM216', 'MTM216', null, '$2a$06$C2KeNDfnN7qTfrKvMqvcBeEaxh9wUXy0/lU3RWa9A66H6.yjwKXw.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('89bc0f22-6243-47fd-8cc6-35095b88df36', 'TAP157', 'TAP157', 'https://search.google.com/local/writereview?placeid=ChIJ-yfUAQCVDzkR477uH_paICc', '$2a$06$R6RSCPEz2b6We7LxI6yOqeU534PMpIC1XEMRrTgOf.ACQ6Y8VozAq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:14:34.985864+00'),
  ('89be5561-3867-47b9-8507-4759c0fecf54', 'SP334', 'SP334', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8a0780be-5eb8-45b9-bd75-d1473ea517de', 'TFF090', 'TFF090', null, '$2a$06$OIdKiJ3M9DH49WdJbCzV2OmOaR.c0Fa1523oN2lwMBKzvL.hgu1xK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8a29a0ff-ca5a-4899-8cfa-bb68d1653fb8', 'T180', 'T180', null, '$2a$06$Yn0iDXcgwXO.doH61SLarOR7uIc8ZH5Gxk2AvSAdClxmDotc6Q2ae', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8a2cbb36-5221-4ab8-9434-7de5200c5c7e', 'TFF103', 'TFF103', null, '$2a$06$RAOcFOasu6LRkL0zleMloOZOzlZWC6GSQazec.cbYb9BscaueifUa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8a800cb2-59dc-45d6-8134-72c4195c8f62', 'TF05', 'TF05', null, '$2a$06$ChGPtylZAxQqYavlB68qiuCMZKscGRTcedwOQLBJzdD.YDVcOdc4W', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8a86e757-99a6-4b06-9f2b-5f099ff5b859', 'T072', 'T072', null, '$2a$06$wAaj.F/0ibf13txkE1Q/P.YXhry44AIhl6FTY/jVl64rmyFxjhE2e', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ab2235a-42df-458a-beb1-72f04a7be802', 'TFF067', 'TFF067', null, '$2a$06$aNfGgatCpCs0JKHd9K0WNeKOvzIZv0yWUJFd5yQ9fK9Wg4SQkMxr2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ab2fc50-fa9a-4ff1-99a4-d75879730472', 'TFF246', 'TFF246', null, '$2a$06$aWxGh9TkcvYnWpApN67Fje3QTbBU1bMJ4Pov4v3Znc9wxugJ2Y92G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ad5b818-b359-4904-88ac-0964ecf10949', 'TAP046', 'TAP046', 'https://search.google.com/local/writereview?placeid=ChIJwcIy64bBwjsR4-eB-pdzTOo', '$2a$06$S5lTyntxytIKymn9y1RcH.lLlFdHSOErQ/TLwdW.5H1oNrJrnBMs2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 08:14:47.063514+00'),
  ('8b12d868-229a-41a5-bb8a-6d695d1ab76c', 'TFF108', 'TFF108', null, '$2a$06$gHnxN2kCaIIOAVf/3rVNDupE2t7U/vDCGf64XUYPDCzLd.uPKZR2u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b146d28-0762-4697-8033-c1a8b7016912', 'MTM248', 'MTM248', null, '$2a$06$Ai.RkTTgA0hZOyYaVDgEiOd/HhmdOV1KrL/80.nbSx8TIlm4orMmy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b301008-c406-40bb-8e69-9e2d812f2455', 'SP325', 'SP325', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8b320715-4ab9-4487-b01d-1b80310bdddb', 'TFF279', 'TFF279', null, '$2a$06$pZRKls9cFDnrHqj8hLithe2Exwj9iPRzpCUn/dcjWNkTqNRIdB77a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b496c47-0d27-4a24-95c4-fc4f0f020eea', 'TFF460', 'TFF460', null, '$2a$06$fwohtiRLVuqLbyBAnpUStev2nntuREOqHImmXFUnPCeKxS6dvwL6W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b543be9-2506-4334-8279-2aa2a441f66a', 'TAP100', 'TAP100', null, '$2a$06$6wcQONDCCB7b/fTHeNmwCenuwV62d5h9lTcsCftrm2P7VsbglkPqq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b678afa-6533-4c87-8292-f55c987d5402', 'TAP359', 'TAP359', null, '$2a$06$J2WqjIkEtwW22N0InDNeqel9HmW1VqY6x7Nr7FVFJEMWycohg4hhe', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8b92054c-9d6b-480d-9540-c9e042e744a9', 'TAP139', 'TAP139', null, '$2a$06$.Z9TLITB1wQU3gHzLOTeGOsWJtdfhE2lUKwjZgzlHqEPHO669iYEC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8be2f0ae-227b-4d8e-9f19-24eccde91b70', 'SP043', 'SP043', null, '$2a$06$XEa2DdBkY8R72iqO4r3AFea34lvF6GtsmiRHlI64W0p9J.RrJP54O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8c666dbe-2964-46cc-be95-20d725f69af2', 'TFF331', 'TFF331', null, '$2a$06$uwYsuy8qsmQlsomWbt3bWeSkY/xKbEnwoTaUAmpQn.EvwZRgfj0C6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8c82005e-58d1-4a8d-9cb5-0d97fafcb402', 'T195', 'T195', null, '$2a$06$zCQtWCbE52c72nD0D4s3r.2jKG0.1KS.NhY.gcUXwsKA376OupdNu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8c9180a9-60d6-42b4-a16b-84ca9e20e833', 'T085', 'T085', null, '$2a$06$tCwdIyKYLGdAcanpX51RNu5rMsYbzhKaVUsaVJwkEfkvNVbKzBi0q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8cb51231-32ca-4db5-a023-d24d5c0f1396', 'TFF209', 'TFF209', null, '$2a$06$zTobUZghdQJ05eB1GOBE9OHOobxxKkFHxIleam73I9ImQhn85Uznu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8cc58229-49f6-44fa-9063-53e3e1516e84', 'MTM148', 'MTM148', null, '$2a$06$5AJz.plq7//F7H9Ba7L1LeBCp42J3TG.ycwHWSZ1GxMA7mo536hjC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ceb557b-5cfa-44ba-a1c2-924b098f0a94', 'MTM165', 'MTM165', null, '$2a$06$itluCEK0KIH7f1qqLL1ZOOlnEW9aeIiakFP80xKJP/DQ4sVGqWzma', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8d0f5531-8a02-4247-8e15-7ad8e88b81da', 'MTM123', 'MTM123', null, '$2a$06$2TvAhIdQR9LIyAR2ZfGwbuJYFMDIMAun4zExn2I0VaDxpPPU4gu86', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8d335272-464c-4bbf-8b8b-8e858fbc1c6b', 'SP487', 'SP487', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8d6ec007-d739-4909-a659-c7041a6cdc0e', 'TFF036', 'TFF036', null, '$2a$06$eqTPS8vfcBFh/Xrpxgb7ruGEQYJTdYtOBh7H15VMoifV1cmpqOeCu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8d8239fb-302b-4571-a1ad-72239a67fa95', 'MTM371', 'MTM371', null, '$2a$06$ipc1oU1DiWofRBAFehLVDO41MvjmIl8lzBiT1q4nHB5FySNLdI5SC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8d86c41e-382d-4460-b8c1-9232acd9c1f4', 'MTM160', 'MTM160', null, '$2a$06$CBkmaKLC0.quSP6wonA38OkEl.5B694tLlUx9zFueevwpIqQ.w.Ju', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8d9e2307-f8b0-46c9-996f-42a3382ac878', 'SP337', 'SP337', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8dba1680-eec7-4cca-b6d4-8da2f41cfcad', 'SP296', 'SP296', null, '$2a$06$GpDPXZQ7Kz4aFLVR.z3WA.6vzvFaa6eni78EimWAz068Gb3B04FZ.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8de73490-801e-4160-9464-e1f3d5b87ce4', 'SP171', 'SP171', null, '$2a$06$3UFyTHA/SKL3uXFpfvX8HuA8O6G5e5SNDB4.fJ0l0Rj126aEubLDu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8df4b272-90b8-41a0-88f4-0be5b17950eb', 'T082', 'T082', null, '$2a$06$M.ABZ0gQJy9Te3VaEHbCNO0JFqxOIK3tILCFGkSdog3f29Up47sJa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8e3b5022-fcc8-49c0-ac35-85faaf5b2ec1', 'TAP026', 'TAP026', null, '$2a$06$Vu19mWVgjl72f562SV9oUerYc08XhFNjy22hYXfs9rN14HUIilAES', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8e7968fc-1e0e-4244-b95f-9db9cd103f9c', 'SP370', 'SP370', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8e970af8-86b5-47dd-8a22-8eb0a70fe937', 'TFF225', 'TFF225', null, '$2a$06$pETl1RbKlme4SvxKhhZfieZbpc8ldTar6y0NHpBWmeviIHwrAx8lO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ea1095e-2ab1-4c95-a00f-793856a253e4', 'TFF184', 'TFF184', null, '$2a$06$Y2Lz8UEUpdvd0eorildQJOXmvD2VAGT86VU1omG1g3hi9rlWinNre', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8ecb13d2-d71e-4619-974c-88b763508c23', 'TFF296', 'TFF296', null, '$2a$06$noCYUc5.ctp31ly7mbGeheTlGYar2yIdyfusX3AuzI0GSuOFbJZla', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8eea131a-e9d4-4ba6-9139-0262dd6b3cf6', 'T259', 'T259', null, '$2a$06$xfOQKDJwIMKGtfco5s.rOuYqjPaQPrE6SkeD.4b9YN94nUoGqrEja', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8f085e73-b1a3-4de7-a1da-99fea1c671bf', 'T206', 'T206', null, '$2a$06$56HhtJwejd8MCXKwpdUJi.owZ7me7SK8TjbXShx3mPWjpPoUwe7fe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8f1f5849-2062-433d-a42b-972d6c595c5a', 'SP138', 'SP138', null, '$2a$06$tDCGmusZilpP/r4gOVbSAeTVkar.2b9tu65C4P87LEFpmHN5urS6q', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8f245147-5767-4cdc-af10-021746e686c4', 'TFF408', 'TFF408', null, '$2a$06$ImF5I0ur8xrN67cG/tDVVO939lOlEa7SBWcZ37LYGToraUMOwdBEa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8f868e76-d2c2-4f94-bcb1-b7978dd53d22', 'SP437', 'SP437', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8f89fca5-e2a5-451e-bf53-a1bebf5fd236', 'MTM191', 'MTM191', null, '$2a$06$iH6FXsOXKlJ8HXMssGWBmOn0BubcOy3UTrn2b572Ae3TPhqmUPJVS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8f96b7e7-af58-45ed-9315-1b676895fe11', 'TFF381', 'TFF381', null, '$2a$06$/ZL/0kxHLZL9WZTXnFOHnOKXEXHGRlAM8z6nfYXHvaGyvjm43S32W', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8fa6138a-af43-4015-926a-c0b5ead23508', 'TFF489', 'TFF489', null, '$2a$06$DWqCQqXCvmMQ9djrnujIVuxKsk0FAbaCTfmBz0hGOubT31OXycTC6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8fb9c5c5-c56b-442d-9195-ef65913345da', 'SP321', 'SP321', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('8fbf5569-c4b9-4c95-ae0d-5cfbbdd9d167', 'TFF437', 'TFF437', null, '$2a$06$n7qpgL8pwWU8qUw3Gz5U.eGL9Cihz07nCI4CpEOrJWc0fEK2EEEyO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8fcad9ea-5acc-4fb3-8882-b9b0644d2d65', 'T073', 'T073', null, '$2a$06$Lo9XC1i0SlYWqeiGzINjT.2S2UkYPXIKlNYlrbC5oS4zhT1/7FoAq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8fd7105c-482d-480b-bf29-43058c28cf13', 'T105', 'T105', null, '$2a$06$v78e7uzHGnFF2mOQ8VEV6eJyM5SWaD2qZuxt0hbFAdkkZV7X1vxdO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('8fdddd19-96fa-450b-b23b-6037dd47ec79', 'T169', 'T169', null, '$2a$06$eCT.ls7BceR6/TuoykJnOOigh0b3o417fKCFxTsEaUJ6VqLpn6.ze', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('90093f43-2708-4ced-a383-9aa7a8cf9bd7', 'TAP087', 'TAP087', null, '$2a$06$H074ou/cApUIWpovdNqYAuVgoHY3KgaC.Tq8MUwPXU4RrQTsZBt0S', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('90115616-c034-49b8-bc51-79e81e792d7e', 'T193', 'T193', null, '$2a$06$OQYGLd3hHhp6Hpux1VxvuuFtGqXYi.pMYrueicMtNeF1cpW.noh9S', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('903da5cb-77ab-451e-9dbe-33839b5c862c', 'SP388', 'SP388', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('905527dd-81b5-4789-b8f2-fabf8dd1b7ff', 'TFF392', 'TFF392', null, '$2a$06$ycUrB9bqmdUFDBescs3gFeaLp5VxA8BuimoLR5C3uIt1X.p5kQUu.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('90578590-b955-40ac-a6f2-7fcfb3cdc785', 'MTM436', 'MTM436', null, '$2a$06$qmbxbYWXjX2sEOnplBKfhuplHKgb9adrHdciQZVzH/CrLjlFAsKPS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9063ec62-86b5-4ce1-b8ed-7c488c8d0c40', 'SP469', 'SP469', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('907804b4-87d0-420a-8c51-d394df7fa056', 'MTM124', 'MTM124', null, '$2a$06$k6WfdIAQuM4e/OOlp2TiOe1EI5H4loYoq/6FcBWlB7b1SgNOE/ijC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('90867e67-429b-4804-946b-3ec985eb8e9e', 'TFF458', 'TFF458', null, '$2a$06$aXJlHswnO49vBm40uJDPbOITUG8BPTbPm.YFCvn2opnk4S0UZy7yG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('90e8e6cb-bccf-4ae6-b916-d877a1d349c8', 'T011', 'T011', null, '$2a$06$4ll6rMJcpfDJj7Xx2rjsoehZz6DmFGLRJZn.TKVLXclGqLqnm4bdq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('912cbd32-a72e-413f-9a93-8dc4677176f5', 'TFF002', 'TFF002', null, '$2a$06$47JpHXh6s1MMW7akmsREF.EcZ5e29aLlKtwyDssQfunQ1a9lJMQ5C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('915f1c2e-2957-4b4a-b81f-dcccaf529335', 'MTM429', 'MTM429', null, '$2a$06$lPNIaBzQ.i4.QverohxE7uLcw2JIg3JS9sINyimL.tQm89h3k5oCe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9186f712-4499-4ebd-8b9b-4d48687fae75', 'SP056', 'SP056', null, '$2a$06$3vav7YfYDA4ast9/wk16FeXUE1QZx7hLQT0o1YV1CNltAkuFYcyOe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('918a3f85-42ac-47f1-a889-99dc71156289', 'SP300', 'SP300', null, '$2a$06$5AXZmlwVmffDrqYRJraHE.9qI.IjTNBJ2TeApIfAdGHXJt1h8JUPG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('918d04b5-3a13-4d04-8f2c-a9ca99dde1ea', 'T055', 'T055', null, '$2a$06$9TdDQEQrv1V3xtfHZHZkLe57/mG/lXQvA7io5FEx9Gpv5oOSK64dO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('91b23bce-8107-4584-b96b-c1b94c921bfd', 'SP389', 'SP389', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('91c73d11-8afd-466a-8378-439d5d916de3', 'SP260', 'SP260', null, '$2a$06$k917M3uxe59ICMXiqlXjE.khRecTVSaI8Vo9jctPUjZ4Sx7AYbUkS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('91f8e40a-599b-4052-a9c4-5658faf392b6', 'TFF323', 'TFF323', null, '$2a$06$Wu/T4FCWQa.uSUQf.3RGtuYvvXsT5IvPq6ywKsBneY9NWzjc98mZm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9203905f-369d-41c7-b4ea-66ca00c02e7f', 'MTM254', 'MTM254', null, '$2a$06$vR2jDs8JT2N4NvPzi6P.9ux.dFHZOoQfWacEVZj4JcWKkGBYX2syq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('921c540c-6aa7-40d5-937c-a151ecbe2752', 'T237', 'T237', null, '$2a$06$psrV7LPwXmoZevbKiBx0iOSCE3eMG.ykczpLVy4j5PlVuGxaS3DLe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('921c6737-d7a9-4a1e-bf4f-c21d4c043b98', 'TAP389', 'TAP389', 'https://search.google.com/local/writereview?placeid=ChIJE09uopvr3TsRN7b_MLhEjm4', '$2a$06$nWTTOfF0OblUZ6zspHvWG./bO0QnVcYl3Gz6cnyHGNBNzmSzvMc5m', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 08:28:33.368601+00'),
  ('92354d36-d34f-4dd7-a9b0-f22040145885', 'T281', 'T281', null, '$2a$06$bcARBc5.UuxdPIQqwrcOU.NY7/Bexfw2pTAT.YHET9rT54hIdY6S.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('924a1c3b-b07f-4fbb-baac-2ddfb98a03bf', 'TFF500', 'TFF500', null, '$2a$06$swproRPJvIeMVFLFGkoj5uDRziNhe4Uq.QQr/fnfeuObiOhQ/pM3e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('926457b1-4cab-429d-b28d-687a3e0e8334', 'SP118', 'SP118', null, '$2a$06$tTUdeiSqHyb5rKXVOlE68efbTHuCZbvFxrp0BrzfhlF8gfxlxRLoS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('926f1440-d033-4c54-8ebd-49eff7ec94ab', 'TAP009', 'TAP009', null, '$2a$06$7zBPCIiwINT8mm1KhjhR.ebH8GBsN3UAYttGfRQWxGSQoWx9f4TbW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('929bcc33-d28a-4088-af8b-4a62da4a5e43', 'TN24', 'TN24', null, '$2a$06$OUXqIzwL5ut9smcLtB4tVeqDZJ2BxUDvG7tOtK1G0KbpHn7DJzfCK', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('929edeb8-b993-4f2d-8478-b79311d4bc66', 'TFF289', 'TFF289', null, '$2a$06$orgCdt4/D9Q06L6HySJF.ekjOWQr42J2WxgtNv1s.6hRcnH/2r9vG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('92c71dd9-cf5b-4c8d-98ed-bf11e76ae18b', 'MTM337', 'MTM337', null, '$2a$06$qF62LChojP.R.Gs01hv./OPH1RGDibyost6l81LuHlahnalTaP9/e', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('92f508d7-b04d-4649-94ed-b9cb6b5887a1', 'SP129', 'SP129', null, '$2a$06$ryqSFvY4KHrNArQ8TIwwXelwnicbVxv.yCDRpAai6Z.WPeuP2FGrO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('931850fb-ced2-4159-a707-26b87330c316', 'TFF369', 'TFF369', null, '$2a$06$bYG6W5Lq6i5aXaVM7BpmGOMI5kRmnMdphrh/7yNwcIlzTI62FX3vC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('93256e91-8bf2-4d9c-a1e5-187b7de6e2d7', 'SP429', 'SP429', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9349310e-b21a-4f7c-9d1d-6001948370e1', 'T034', 'T034', null, '$2a$06$QDpWAGMb6O9ryot6tqaab.YFv/Y.O82QVKDeaPd.6fiY/aEskLKfO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('934a3035-da28-4e23-b370-440a19d9ef5a', 'TFF332', 'TFF332', null, '$2a$06$8YD.ukfsGvpmW225vZfKZOZs8zcrhD1cupYComqZtndm0XgerW9YC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('934f715f-fdee-4795-b9e6-25521fe54469', 'SP003', 'SP003', null, '$2a$06$vDqVQHg9Zv2wWYprKNLR6u5pnK4o5dKh8SUXbZrDpIl.Q5xWOqZeq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('93796412-4e73-4095-968a-32f57235a7fe', 'TFF229', 'TFF229', null, '$2a$06$oplVTehmHD2e9N1b0Eek6uVINoamU/xnxrSU31q9QLJZ9C5Iddgmm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('937d21c1-c008-4c4a-972f-171b00a690c8', 'T080', 'T080', null, '$2a$06$/Nbj4eLkk67YICRo4zWPcuCinKR4dvsukdcssmbcwJM7/14H2K5qK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('93d7e7da-0ee9-4a45-8883-a7ee4d7fb395', 'T265', 'T265', null, '$2a$06$LR1wilz13iaNRv2PgIG7c.jfznJJMunURhpMKtJWYpH3nd.NsAO/2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('94079d8b-3d36-4ada-95aa-f737cf6b0869', 'MTM416', 'MTM416', null, '$2a$06$O/D1XojgIkm8zK4iQPJMpOgmCzJ2N6TLK1r0BXpeQAlaAfs6T4TMK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('943b2f90-b6b3-4149-afda-d62082963d32', 'SP230', 'SP230', null, '$2a$06$iVjdtrYMq44BrY7dDtk2ee9HB84D1yuMPp8RuW/wbN4yxg.5PaNhG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('94876cfb-f3ba-4c11-9c62-dbb2377bd8aa', 'TF06', 'TF06', null, '$2a$06$LbhYRpF4qEZCvufItgokY.b6A3UZcZfbuYB/gyHv8DCXEohaGGW5S', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('94b843e5-bf53-476a-a414-d571be2f2205', 'SP474', 'SP474', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('94bbcf91-2bf5-4d2f-b406-9b4269e7e2ca', 'SP250', 'SP250', null, '$2a$06$arjQAdZ9FB2KG2Kv5oxQCuURGXOKxDMpu0E.AdJXTlrqgHF4ogfEe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('94df47fc-f6bb-48e3-b241-edae45523094', 'TAP224', 'TAP224', null, '$2a$06$NjoqBV0QPYXdFIJz/pTbq.tP8BauyjrCpYqtkHFNBiSgEjqcyvup.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9514cc11-4f73-46e1-8b48-4a6029475971', 'MTM333', 'MTM333', null, '$2a$06$W0EoQrLqQW3TfcUUoNuvneD0UzwrZAtXZzZLybtBZNCGGnh.0Lxeq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('956cdc58-6ddd-46a8-adcd-4112352fd6d4', 'T075', 'T075', null, '$2a$06$mkB5el8NVIG5c3grVew3duoC5G7i/idUf4Ys1fQtCcYJG0jmxSiia', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9578b088-2146-4d6e-be15-f35bf728124e', 'TFF483', 'TFF483', null, '$2a$06$F/HadBGVBbfbZrvrPlyTpuAxEJl1yIhodSVO7LrqPT4ZfOIpZ354m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('958b84a5-3560-4e08-9e19-b4b462ca39ba', 'TAP057', 'TAP057', null, '$2a$06$oWiTayF8dd3SzaritwG47OM1PW7wyYAikwELEW6fQeSrnbagrFal6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('95ba836c-c49b-4de8-888d-bc6fd7d20d04', 'TAP144', 'TAP144', null, '$2a$06$jqHcuBG2VW0Qnh8AQFnbi.diZymn5/VCd/tGR9i6SqWaVYRu6Huqq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('95bb50c1-8f24-48d0-afed-86f422eb64ad', 'SP312', 'SP312', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('95db6b2d-05b0-4a42-be37-8f6541beaf33', 'SP360', 'SP360', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('95eb89e5-719f-4bb2-a02e-f85685a1c143', 'T262', 'T262', null, '$2a$06$EZw67PJrDggxOu3RJ68E9uchHWb/OvJGBeyBWwQurQOWsMd9n/NdO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('95eec665-68be-49b6-bc9c-f4c3cce27167', 'MTM438', 'MTM438', null, '$2a$06$XBEKBFc65GhHY1IsPZ8G7.kCjSAxX3zQ7RxCdrRZI9Pu2teuB410m', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('95ff5c8b-05ba-470f-95da-803ba2e7903a', 'TN18', 'TN18', null, '$2a$06$q44nmlZNMFYpN3rTIlj4aOgwli4yMWwV1MfdRRtbmhJR6h0oQensO', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9611d56b-5cc3-46c7-a09b-f782141ba0f0', 'TFF157', 'TFF157', null, '$2a$06$ZopOocDnxfs8MDUVk3ew2uvAQD3AIxVjhDtsqr7rkvsh56YlMte3K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9653e713-5b01-4475-8732-12d0df7e6b5f', 'MTM270', 'MTM270', null, '$2a$06$oPq6TO0cJYsHXLhgkqm/7ua3PA/rtP5AZTKD/odHrFP1OTPj.tbPq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('96b79df0-7c3e-4ec2-849d-00f5674e1598', 'MTM219', 'MTM219', null, '$2a$06$rdkk/Q3eZaFlH4zvaKDjGug4Yds4A5KcE2wic1NQzxH0PUXT6XY8S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('96c0f71d-b589-4012-bd54-20e1cfe0abc3', 'SP409', 'SP409', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('96d814c5-a1ff-434c-ac4b-ae0b1d2b25e8', 'TFF177', 'TFF177', null, '$2a$06$9YtoeBH1hiYlwovwevDUX.vaXly5TB/fGWHS325WNZubEI/hcw9Q6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('96dc9835-0e64-4384-975f-366b569eccbc', 'TFF453', 'TFF453', null, '$2a$06$WDWKVLnOLJMWBAwxwMLJKei6d7Vj9rsH85Qobgt3uViYa.Loa6ax2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('96fa6e75-4d4d-4f79-8d50-911325c25bb8', 'TFF455', 'TFF455', null, '$2a$06$TBDU/5aXY058oMS8tI.gEueSo2MAW/LAMgP5m7xmzVVjH7oOrbagi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9738e433-5b08-431b-be4d-856b62082edd', 'MTM169', 'MTM169', null, '$2a$06$5jFjEN9epcIBX41IBcVc0.jgbErc/r9b4Moy9WtIjrBK8Ux0d3HzK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('97544037-e1f7-4826-8ff6-1f17843ff58e', 'SP403', 'SP403', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9783f903-fc49-4975-a899-4c351f08635d', 'T140', 'T140', null, '$2a$06$Y0lRG.QJVEoVScRfcs4fZeyDEZ1rE7laA.qjNUtuDM.TLJBuwFj/6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('97bf467c-6ada-4c87-a791-d2076e48c4c4', 'T123', 'T123', null, '$2a$06$AVO3uHbEgiywAK4yMtwX4O.xkm0HGWKBThQPsZo82q83esYKu9u1u', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('97c6511b-cb45-43be-8bb1-098b7812ed30', 'TN04', 'TN04', null, '$2a$06$0a9M5PnQUjd9FRwjSFLcaOScdZUFLYTO.IJPXB19DqIqm5r2Vfk/a', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('97e8d877-9278-4563-bfe1-12ab9b18c1cf', 'TAP243', 'TAP243', 'https://search.google.com/local/writereview?placeid=ChIJB8mZAGXrDzkRvXBsxOAiIO0', '$2a$06$EhK1yJaZdoNGaqNHrjGkDOTHwPvQWUri8YeU/imNbANc/QLjWnRMu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:15:19.922333+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('980b822d-c2b4-4909-b64b-de06028346a6', 'TAP278', 'TAP278', null, '$2a$06$TBQt9ZzRouUPgzONQd6vE.V06LHdTJqdNd8majVWd190faOqFPJri', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('98166a95-3058-4540-a791-9e65d8d3983b', 'T248', 'T248', null, '$2a$06$Gd7YxXjyH/DZxKduRudZsu7mlNhqHKmv1k9wCZ4/PllcPM.0aUXmy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('981df0b6-d229-4bf9-85c2-7ca2ba2348c5', 'TAP299', 'TAP299', null, '$2a$06$CUDatj1RwXxpwvMa2U3RdOasSpXYXwxCAK/prki0QFGRoXooglv.e', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('98404bb4-bf79-4efc-9956-0e13104a2dae', 'TFF326', 'TFF326', null, '$2a$06$1H7eH77JBnb4CxF/clBSEOe6PbICPcZUOk9.LIZmnCdRv/kyRiuSm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9843fba5-84e2-4180-b6c9-b337858d9d05', 'TFF371', 'TFF371', null, '$2a$06$RiycyiwAfMp9KOBqYfzOiOrtMuv/vhxJ7ksH/mtQ772xt6fOlMixC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9899edd9-bbdd-4198-b972-a0e125bfe40f', 'T176', 'T176', null, '$2a$06$UnOzBxsM9pKavLwWuQgv7uFYE9/HsoHaUjnPB7j6vZSPgAPBCm7jG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('98d79110-868a-4f34-b2f7-a78cf9ad0c58', 'SP110', 'SP110', null, '$2a$06$fzyTPxrVqqY11Fn7oxLwU.ei3/qWEz43KYEGyVASqYvCLhAHyHkXy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('98fd302d-64dc-4a9a-a92b-70ecced5d439', 'MTM297', 'MTM297', null, '$2a$06$837Dtopv8gec5dBaHTpD.e5nXaLG4/dsYYed8LLDqWqtkFRztILYi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99152d62-4295-43da-bd54-e526bcfeba15', 'SP458', 'SP458', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('99738872-6f15-4baf-87a7-b93c1b33331a', 'T047', 'T047', null, '$2a$06$Nwih6h2tCJoCY75VmT6G6uUHqSZiCRd7A/V5UPLG8Vrw71YfUewu.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99792e0a-39a6-4a7f-828a-fb0275e5970f', 'TFF464', 'TFF464', null, '$2a$06$IPfIu.RcZibcB2L7ulGRJuF.qmU3tRBsbGqtQxWyIqiwSBqtQRhfy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('999c27d3-931c-4122-b919-15ab6f88c3f8', 'TFF477', 'TFF477', null, '$2a$06$T9pTW8211PVpI8jdJtS8vejS9TkamLaFgJKl3LjEA.3XOuF2q6ogu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99b2dd25-d387-4685-a726-d8124b1c1e9a', 'TAP330', 'TAP330', null, '$2a$06$nkCbL/dSkd2iCpTCa4fOIe.vKvIAoAILtm5emAE/mChpa9W9zWbDi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99b53dde-ceb5-4fa0-8714-0db63936a669', 'MTM388', 'MTM388', null, '$2a$06$Z/tTxGuCLhvcPBZ1az2lyOPmwE2QeybAHFXhXzfebvvuwumUEuIOa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99b579f3-1f15-43d2-90b6-0eca5216ad9c', 'TFF444', 'TFF444', null, '$2a$06$1PRo6u6IDSG1csyNylfJs.mD6zRflnt20x/sRVsUFcigc10PW65ki', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('99ebb26d-be95-43cd-9bc1-7c496c3c3b3f', 'T273', 'T273', null, '$2a$06$Pw2ycJ0YlL20KkZCe1Qdhu6py0xRMhEPGSgLoouvlLsOq02v//HFK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9a065fe9-6e9d-4512-ada9-2af8f480fe92', 'TFF228', 'TFF228', null, '$2a$06$ExLLXwBDjj6Eh2Yl5L8COelJ5U2XR2SqsCZZuNGXWgWpGJAXij9Ey', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9a26bd8c-7c26-4d32-85b1-07d8b018ca2e', 'TFF068', 'TFF068', null, '$2a$06$c5YAoBS2SWx1m.G5PSno8uanjrEWUqXqF47MFC91f9dXjAAn/VeHq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9a3e7744-9add-4489-87ba-43b9c37ef2dd', 'SP058', 'SP058', null, '$2a$06$q970S7uu7nUA8T7VoHhT2e6aYyaN/kizTTnpQfIwNL0LGb0gbb.T2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9a6874af-b547-4f47-ad61-67a35e422030', 'SP352', 'SP352', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9a756a03-e9f0-4cae-8181-901d97da0a0a', 'MTM228', 'MTM228', null, '$2a$06$FOSg/W0CXelw4urF4dr79OCd/LOX4cT.dpyPW8o9SZRvgTTHNGTpi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9a7e3009-1efc-4fd3-be36-d03d13a0a936', 'TAP279', 'TAP279', null, '$2a$06$6A76ZLGygB8vv6Y7tMxmJeoxShyEqwBfG2sRQ7VZDRvUh7qO22BaO', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ab17ddd-8818-4375-9529-d445aefd11a6', 'TAP380', 'TAP380', 'https://search.google.com/local/writereview?placeid=ChIJSVydOQnr3TsRhaQ9Jz2VDDg', '$2a$06$pUGcIuhVpSDR.OZjud5cn.5s3HONv.Q4ehys5bR/Op7vE32JTzgn.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 09:38:46.926399+00'),
  ('9ad63a93-2948-4cdc-acbe-119a06e462a3', 'TAP391', 'TAP391', null, '$2a$06$y4RqWd/wnhn5ZeQPIijCAui98u1PorjjSty1uHAxSh9CX6r3ET37.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:22:31.771411+00'),
  ('9ad6b077-763b-4f1d-9967-80af35b1c751', 'TFF238', 'TFF238', null, '$2a$06$ICTG8Y8GSlZPF7KSCAG0wu1BcKGCNfSqtAA/7FUqtYDbGrS2Xner.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ae1e256-01bc-4105-81ae-925772d91316', 'TAP067', 'TAP067', null, '$2a$06$73YyekDeC5mm5S7JWafxdePc7.MEYDt8ZIh6rkzUYmQ4FK6O/2g/W', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9afb2edc-18b6-4111-a6b1-daf8d8e57a7a', 'T297', 'T297', null, '$2a$06$dpI9xcUhoE1MeQnj5YFCAuj21l61HW3NiM1pgWuZNPrhL.DyAXsu2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9aff46da-cfb3-4161-9975-80dab07e4e1a', 'MTM287', 'MTM287', null, '$2a$06$qX2B/RI2E4Lxy79PVj/jxeBjOQ4YGGwQRobi/u6CXnj/wYZuOD/LK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9b29b31b-e2b0-4b74-836b-7d8277c3b57f', 'TFF139', 'TFF139', null, '$2a$06$HKNpGfznaXAMbkKi3r5J3ODe4UV64xgC290e1poHRC4s9jlNFbLT2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9b45c9e2-a9a9-4ce2-b9e0-cc447e03d91b', 'TFF308', 'TFF308', null, '$2a$06$rUJ7l2kg0mq.yMMbY.DpveD7C9H83T1CY28nXFGDnlBk78bnK6SOu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9b6e6eb3-6dd7-43a5-90da-ec8761650af8', 'TAP225', 'TAP225', null, '$2a$06$aRENcV97GRrsRva0uFASI.RpGoXBEF4ahKORTk5wgTMKsH5y/5mMq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9b894887-aad2-4485-b4c9-242cda25a2c2', 'MTM300', 'MTM300', null, '$2a$06$Ms7vFqgBzu01W0yJmZXOu.bRkWmEQdKXlbe1NxnfXwOse6k5.gGoa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ba416e8-9a9c-47fe-b150-53ca8863d0fb', 'TAP286', 'TAP286', null, '$2a$06$KR47Dgmx3JAWNpPMbrh/NOm4T2kt8fGbnhCfZGX1kltWOmPaInFvm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9bd3fae1-d13d-4226-8446-1d6fe08f273a', 'TAP023', 'TAP023', null, '$2a$06$lW4lco6zqT8l/IWuzwXi..rN..3ZfpDAMO9nUprX9icPz//EYoUri', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9bd833cc-58de-4191-b65c-80fa03488d17', 'TAP397', 'TAP397', null, '$2a$06$QvSYIk0Q8ON0QTOfM0tnAeMPvxW/7B9ox/4LkjGtoQvEG9mDa4cFK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9bdbebcd-8611-4dcf-8e79-91948063f9e5', 'SP477', 'SP477', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9c019c0f-4412-48bd-affd-76a75a8b19bd', 'SP236', 'SP236', null, '$2a$06$/K3YMHQcLffYWD/WIXfp9.//uteJVCzQxoXCyALvzh5phXEhTFJrW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9c14f5f7-2a07-4723-8bc3-d5b1745f72aa', 'TFF197', 'TFF197', null, '$2a$06$1vaYIQxRn4ED9lGeXWt7feMVMxQXjn3mAAYYTMgVN8JJLZ/sdxW8C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9c3d1701-6a5c-4de2-b30a-68b603f2c068', 'SP266', 'SP266', null, '$2a$06$LlbpFISHP15PbCF1gRd5f.T.GiNEaB8Eg4YHZfc0LOi5juRu1Cuw2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9c5c2412-cf47-4dbd-83d4-47dc6b978233', 'TAP356', 'TAP356', null, '$2a$06$laHOUfEKbgW6Ibsc4VGvpOhoJVJSabcSXF48hEFeDcXhJAdIxa0pq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9c616431-951f-48cf-88e2-67fcafcb9738', 'TAP387', 'TAP387', null, '$2a$06$oEpVfPXbU9IFx0SlcWz7ue7uFrzwTvupYW5TDXvA9zbXMQTFlzmIq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:24:00.345081+00'),
  ('9c793e7c-7d2f-4d51-a0d5-a02b8ccd9a62', 'TFF008', 'TFF008', null, '$2a$06$QWly/sPzzNunWrgKtfG3Weg4scMREWrhJkfAmLmaHpmP/3Iq1VqP6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9c8a4915-aa90-418f-929b-0c3d944ac729', 'SP002', 'SP002', null, '$2a$06$yyq.DBy3BKxrp2sacxnZgOqQ06phWXpm7eLtnyIe/XK9oaqic.fYG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ca89404-a65b-4ee2-8990-d5dc3d3aa9f2', 'SP027', 'SP027', null, '$2a$06$r96uuU6VesxdiyZoiih5q.H9hfOar1775KSslINUIUXF3plLcD4pm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9cc2c976-da72-4713-a493-70b1e52faa84', 'SP338', 'SP338', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9ce633d8-d767-4c1a-9769-339b343a3ced', 'TFF304', 'TFF304', null, '$2a$06$Gdvwgal8v8/tCoIrLKcXIurUVyEzbWsTyYgo424aggJh3MuwQ1Mle', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9cfdf621-83fa-418f-859a-b2c95d2a2a54', 'T126', 'T126', null, '$2a$06$WaohaAhXHI2DpEIzVasKAOUByIYAAqiTyMDPbPCKvw8Sm1/dBvq.q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9d4662ca-ba15-4e5d-800c-c10c8cccb1b8', 'SP014', 'SP014', null, '$2a$06$KlyJYK8rx2TrAaJrwhvM7.3SYk5QoXHsMksa6Os8DiKxpN1LKYDtm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9d66574e-e155-4b1e-891d-b2cf8d35d277', 'T044', 'T044', null, '$2a$06$Ov2qLR8cfafR9vOrV6W3oumtkJ1cjb2VEgSxqH5nc2BHmJ98aHsGi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9d665d11-90a6-4215-a535-ae948f97e0a3', 'TFF450', 'TFF450', null, '$2a$06$Jlo7RmGcMnTiCUskdbc6J.Sxi89Faiq//tU9rMiMoTdJK/4hOtabO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9d69b345-c62c-4203-91f2-576ad08f8ad5', 'SP376', 'SP376', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9d7402e3-8eea-48ac-949a-e137543d5b9e', 'SP309', 'SP309', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9d79e685-4d32-4ab0-b3b0-1362be65ae7e', 'SP473', 'SP473', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9d8e4a1a-3cc2-49a9-b3b0-6f254dc3902e', 'SP412', 'SP412', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9da72c84-1e35-4196-8d8b-08a33e22eff7', 'SP304', 'SP304', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9dee97a6-bd55-4b86-8a88-75ee15167814', 'TFF233', 'TFF233', null, '$2a$06$bmgCqy9oD7VpZ7nFBjFm/.l62sj8xvSquZvlH9N9O3xxTZ7v.HnJq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9df1184e-ffb7-4488-bdae-7d32d09cce5b', 'TFF107', 'TFF107', null, '$2a$06$54hXQxfk8.hkB9/HdVNdn.iW6woiadJBV9tE.GKSbx7YM.kGuBp5O', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9dfdadf7-2ecb-4567-8025-484a5cbd85e3', 'SP445', 'SP445', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9e252ad9-d188-443c-bb7f-f9d6e72cb3f0', 'SP333', 'SP333', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9e31e88c-3d4c-463c-9843-8151a9c5f788', 'TAP271', 'TAP271', null, '$2a$06$5V7fR2Rrja7hiVH6jXrpv.VQQg0.3ch5XV2DxGuLEDDtCfIKMJzve', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e3d4b5f-0e9b-4f63-832a-e7972b6cce60', 'TFF377', 'TFF377', null, '$2a$06$soA072wEvmeTPnYOtGc6OeF/Eq49dee1YNY7w.PeXF/cRif5bLpiG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e43a6d8-0108-41ba-a27a-64d13e05ff22', 'SP194', 'SP194', null, '$2a$06$u/Brn0EeacCmHLIVWNTs4.Ix158s0CL3yUaQ3LdS4Ad7WpkDLeHzi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e462330-9bcf-468a-a031-3a5aabf2086b', 'TAP369', 'TAP369', null, '$2a$06$.0Gw8pgsM1/il8FFQqZtXuZDwrYsNyPjnI4MbEmtpApeXwVvunyQK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e6b41e9-f10f-4b34-89bf-6cc0a4d270d8', 'MTM311', 'MTM311', null, '$2a$06$VMfCxYqwKkcv36mb0C5GKu9oOmzI7J4nsXoNJREeGY9Nsmes7DcdW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e6c2fb9-7287-4180-a848-e075c2a3e08d', 'TAP040', 'TAP040', null, '$2a$06$6K3b5hSQ25xYFn/uR6j05Os0EXBi3rwV9PQhQKOFkTQumZOQkugrG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e814b6b-fc2a-4ee3-966a-71993b8f8552', 'T114', 'T114', null, '$2a$06$vYWf4u5ktQFZEfNSLXcDee.MuBXyXeoMWyf0tMxg/zBMrxZinVdC2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e8d03a0-2112-43b1-8daf-55e8c2c46da1', 'TFF113', 'TFF113', null, '$2a$06$8mcJZxVp.HhFi3xDMJO/J.tUFL8eOukK24KFAtk0HyW/AXlaO7ts2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9e8dcad0-2fa7-4b26-b61f-4c5a3bc5e8f4', 'SP055', 'SP055', null, '$2a$06$FIbNDmloReZiEDzN2v6iEumcmybD98fsMuGgODKbHgUUDuoYYF3Qe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ec90d57-b087-4378-826c-1f44eeba8849', 'SP001', 'SP001', null, '$2a$06$.m/12mqSmIog1E4c15fg/eMN2B7rHEJge3HFVjWkLDURsY36J5ZLq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9eda942d-83a1-45bc-b3e2-ef4167d6f60f', 'TFF478', 'TFF478', null, '$2a$06$kP4s/gE1AqqrsmnYt8k9Oe8ZKFgOIucZJ8oZeGocNCl1DnOgzTfBS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9ee0e2de-6828-4b06-bfec-68aa428fd4a9', 'TFF270', 'TFF270', null, '$2a$06$uKPbOfBjh8Xcv/CBqMH38OIubp8VYI4UApmD6DhDpB2D.h5kfUpRi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9f11ca34-500c-466c-9829-6ed1a0e49ec2', 'TAP016', 'TAP016', null, '$2a$06$FoYhH1ENkxUfHSRBKD5elOtcXpdtv9qbphNH6Zl1Sxp32hW5AtaTW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9f233cc7-eeea-496c-8587-05886ce8e4b0', 'TFF285', 'TFF285', null, '$2a$06$4DA04vr3rDXrbjCBEK6FIOdMhf9O9.yePc./HQC1c6ogyFx6vib3m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9f2a3807-407b-4cf0-8993-54aeef986299', 'SP447', 'SP447', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('9f30e80e-d33f-4c55-bc56-0591f3fe5758', 'TAP293', 'TAP293', null, '$2a$06$bO26F.paNvlVNvEz1K8oDONttwxIK/M8Zb/SPzhnP.brZE2s5z19a', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9f6d7dec-df4a-44d6-80f1-ede94099eb0b', 'TAP097', 'TAP097', null, '$2a$06$zlMP1ltIKMN8NcBfJWAuiO.QbIVfyfDOIc8DWrEcvaHuuSb8J.SOW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9f76c39e-8b7e-4acc-93ec-9812f29c84ea', 'TFF340', 'TFF340', null, '$2a$06$ci5mvkrdxVx53u98th4/pu8M5LJyvR/zVy1JsiEELJzMSiHQJPB82', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('9fc76025-034d-4e1a-8d8f-f6b44b49d958', 'MTM419', 'MTM419', null, '$2a$06$STZdG2LcsAGf.tExw7FwcutEAHw55wxRovMogaNK6dsh1ynbtX6Da', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a00e3e80-2fd5-4f7c-b50c-8f6042f6604a', 'SP336', 'SP336', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a01edec9-b4d5-448d-b49e-ddd2509641f0', 'TAP254', 'TAP254', null, '$2a$06$Ta.LLfWYF/jpy.PrGsRNUOOrFUY7q/9xOa9D2knJU5qs2PGAseElu', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a02c4646-e443-47f1-932a-5d697e5b3194', 'TFF406', 'TFF406', null, '$2a$06$AbLx9LqldQMgki5H/CwuBeLcGq3lrf2YLGnZHZHijwi8g4FzKfgeO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a03311e4-e1d9-4fe9-be36-581dc02db183', 'SP278', 'SP278', null, '$2a$06$8bk6eI.0MpWkmSCISpNJweHJfdSguZdh9TZTP0TGAg5p51ausmrbe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a096d5e3-692d-4168-ad40-eb5e95822fdf', 'MTM409', 'MTM409', null, '$2a$06$XyaJ6P19jLl2Gn0gsIGiz./Ahdo6DtPceQ.9zqDURBqZNn7pjet7q', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a0a8effa-71ee-4da2-a591-63eb7515c4b3', 'TFF187', 'TFF187', null, '$2a$06$jBa0JoSkzLbTopAzFXihVuV89K8ibV/KCzdtz8yLW5ScEuerVaZGm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a10195d7-bbb2-412b-bdc8-1277c2a45664', 'TAP385', 'TAP385', null, '$2a$06$LpkOKYUjxXc6khbjIVbw2uC3lRxL7YpNhKA44plfeRyDC94VG7sb2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a1446a18-aa02-448b-8f5b-f722f487d85c', 'SP351', 'SP351', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a1886bca-5f11-478a-8905-3f7f513b383c', 'T163', 'T163', null, '$2a$06$t0kvuJeEeBVo0cdv9SKbSON8DgffmuTwqshi.XpjM4Ph5ZZA0J.WK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a1ca4e5e-d55a-472b-9bde-3e74c9626b37', 'SP135', 'SP135', null, '$2a$06$bUJJpTwHdXQMrEqeAlt0ce9qT5WANg6K/55y7vHRZCfo/rqIhoI4i', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a224520f-2521-4f96-8962-68c7c5eee7bb', 'TFF163', 'TFF163', null, '$2a$06$lMqOr7.50OR1WISGCIbypOMPmsbKy5E/K2d36hTxwj0JDiwEnqjYa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a24c37fc-13c0-4170-b379-9e3be7199db3', 'TFF227', 'TFF227', null, '$2a$06$XxodfkhaGlaxk17aDtEuGOeg7g2v2k45IMBCv8t3uKclG5DrTbkze', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a252a54b-d47b-4932-ba93-9b40335b223b', 'MTM292', 'MTM292', null, '$2a$06$PUqKWKNSqtJ7LNqn44a3Oe0d28ps/4bzdm6mcKKMjJAfCygZU/sre', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a260f3d1-ae94-438c-97e0-56a8599902be', 'SP306', 'SP306', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a2810137-7d60-4ca1-a39a-2403371bc353', 'SP198', 'SP198', null, '$2a$06$Dt3Vxk3WXRxLo2MlVbfbNeIB269yFaa0qAkr6QrU8piRymLZaFnPi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a28ab46b-47d0-4674-a411-6613927d55fb', 'SP211', 'SP211', null, '$2a$06$SrAWlvvFP52.5DvVAu5ptemVVA.TjmojmlYBPNCI/jwe.0/CfLdHS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a2977a2c-25f7-4cf8-aa62-9b971d2a3ced', 'TAP120', 'TAP120', null, '$2a$06$GGTpFWwI6v21oLF7grgi1exHRMNhsqQ/Bl0iU2MFbHUtKu99ojOmm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a2a7f882-55e1-4179-bfad-d66d407d29c3', 'SP262', 'SP262', null, '$2a$06$tlLXFXuQZsVdHXZ82jWppedq6APZyhWLEHorkiIugW.Y8/Am8a7Iq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a30be465-1082-4955-97f5-7d698f1285ca', 'TFF404', 'TFF404', null, '$2a$06$7DbFGG0cpPlLStVGmHUXG.krf921/uEI.nKXjeXfZTJ7qZvQr810m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a31041d1-b58f-4b78-9d3d-75411f78d7fb', 'MTM359', 'MTM359', null, '$2a$06$B4MOT4mmj.K5RSDwJlHuu.DgbhLxXuXpE2d3nEqeso/YCo2L8o2ji', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a3126e66-371b-4bab-abf4-eb384740bce5', 'TAP117', 'TAP117', null, '$2a$06$Y/t2.IlGsIYft48nl9wGreHDk9ur0aq1ZNAjFKyD1Tp8r5Phuxtly', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a31b2f11-c85e-4dd7-abf0-a25c8f4fc8e6', 'TAP184', 'TAP184', null, '$2a$06$dGgMfbwEQGeMDQfAw3QHKOTBG1QS6ECbjg3QuoZ9uUU9s.YjLBfdm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a331ee9b-ed9c-47d4-87ba-668b6d8b90d0', 'TAP153', 'TAP153', 'https://search.google.com/local/writereview?placeid=ChIJeRBt6y_rDzkRiAhrj4v199Q', '$2a$06$YUMON4gSTrfhjw65ynrq6OqKfNVAEmRbNkFuXK5Q5IoOUNkktvxY2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:00:58.635717+00'),
  ('a33f7d73-23ae-4062-b6d2-2c58ea174aa8', 'TAP316', 'TAP316', null, '$2a$06$lvqTsXcnyRO6et1lqVL3OOx.Rq9sCGX1WKNPlDTjE4N.701BSnb46', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a34002f8-eb96-422b-b756-05708a742389', 'SP454', 'SP454', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a34f607b-fe2d-4e53-8e6d-52e426b785f0', 'TAP334', 'TAP334', null, '$2a$06$18ybj68NZlgn2zoo2XPdo.O.vXFH7xw6cUXthKFzmWJZSZI1U9Ltq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a388fd2a-76b4-4817-b02d-a3c78467ee3f', 'T275', 'T275', null, '$2a$06$JB.M1pbZCXCmJvsKfwVxwuGJXk6tMBQTjOubix7lcuQSU6i62wR3G', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a3cf5d28-cf51-44f1-848c-f28db4b54e3b', 'MTM451', 'MTM451', null, '$2a$06$pX3TCt52x8b.iheoutcC5OAHBYWJ0.B4RwJux9XiqDIPKvhKyjXLq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a3dfac60-7163-4427-8b47-df747a3734a1', 'T229', 'T229', null, '$2a$06$ktGf0RKXci3pZ0UQ1hWMMealO4jTPi9CJYvLsJ.RR2k/g4Ptl/W.2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a415a11a-67b9-4422-892a-8dca284fd580', 'SP329', 'SP329', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a426c4a8-2410-41a5-b223-3e608eba3870', 'SP016', 'SP016', null, '$2a$06$JYI34wjKuD5eGfgQJu5snexGfnsezkpBaeJcDNsuZxuSztyxdFQ6S', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a468ef46-aaf3-4417-a57b-1274e9c109c5', 'TAP019', 'TAP019', null, '$2a$06$4.mVOvWexamJQisvoHI36.O8j0HY..kN9zEa2A3/VQogCmS2AV1wO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a484f6fd-0f77-4010-8ed5-8ad575f99221', 'TAP215', 'TAP215', null, '$2a$06$1jqbA9MUMsLJP5eqBTz5iuye71JO5KmLdAoDP968nEJ1XgUzfc1a.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a49bdc29-0a81-4790-8d9d-0f1f9f92fa7f', 'SP245', 'SP245', null, '$2a$06$yqFxpm2dSXuPZijhFqrGQeKZplOrGp/ITz04f1v9xuV9wNp3n/M3S', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a4bc8948-25c7-4448-ad91-46abfd6c95e6', 'T139', 'T139', null, '$2a$06$4xD1KdxW4JMWTc8N12dUTuKps0rz52dD7MJEy07vgHN/5TKQqQVYO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a4dd3b37-ba10-46d9-a055-940f10c09467', 'TAP371', 'TAP371', null, '$2a$06$hc98/GhrWkLqsB5w4wTZeuEZj7B4rOE6dsnWHza8Pzt9MFS81zFOe', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a4f3c258-fa5a-4af1-bd2c-166705de006d', 'MTM257', 'MTM257', null, '$2a$06$5EbT3/GQXQ48XO069biBzeAK1VSG2AzfKUTZpOi2FZL0/V2RXTV/S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a4f5f8b8-2572-4698-8cff-402c5e42bbf2', 'MTM452', 'MTM452', null, '$2a$06$zOh2ACuHCAe.mlpN3f74nep3pKUFcsAU3nkz7gwU/.wRGbJmb6bDW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a50084a3-182f-45f6-9be4-0a333f2f46b0', 'SP318', 'SP318', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a50c485d-1424-4bb9-acf2-5eb90043cb32', 'TFF097', 'TFF097', null, '$2a$06$HQyP44pbjd6GeIznwBnyQu27fq.mHTYYLSm88mF1DeR3HgRjXEiqq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a517da08-9a7a-4dfc-bd75-abe1edbe8a3c', 'TFF379', 'TFF379', null, '$2a$06$P6GP4M6OQYj/NFR5PJ0ayOdkzZQC9R1lBicXZlO6gAiikaF6iycum', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a53bb65e-5fbe-4953-9f5f-e9638861d99d', 'MTM355', 'MTM355', null, '$2a$06$iTqyoFLd5h0LeMuP2cJmZ.7j6aIjy5SkfhcnPpt2/SePJWYTfz5ii', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a5d7f7c2-2e1f-433a-9b11-88bf4f966018', 'TAP268', 'TAP268', null, '$2a$06$/BG7Pfg6fHBH2pAdeZOqc.SFU.H1xWzE/wVvopYczDMpDa9uQt56y', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a5f0bc9c-6caf-4090-989b-d75a14bbb688', 'MTM430', 'MTM430', null, '$2a$06$g5pozPKon4b6lHkVBGfFuOB1IOL6f6AYUBxKYpVX3v42tVTZyUhHe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a5fcd5f8-d6b2-4846-ad32-192555e09afb', 'T058', 'T058', null, '$2a$06$.SeAIwOWvE9AblkSm7MK2u9OlK0E5mX0nbxe9bmSvniZ.PvdSPI.O', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6283e06-faf6-45a1-b91e-f744e897e6ae', 'MTM396', 'MTM396', null, '$2a$06$JnPSSmXeUGvdHnNTaJKLzuDpcEUra3MyGPctzIMqN0lf0baelfMvS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6899fc6-85b2-4e06-a09c-59e694fc0e2b', 'MTM353', 'MTM353', null, '$2a$06$NAuQtBtf8.LRDxRnYlMqgu1MLHP9Zre86SOL1VKtgeOr0D2LD1bHi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a68df2f6-c199-41f0-9c48-d7dcbf12db95', 'TAP361', 'TAP361', null, '$2a$06$144OlOOHQFGAsg/WVZAlXOfOYr0SrXnj6C8mvX6b3MPVmkk97OoqS', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a69149b3-e797-4e16-9100-78c94aba16ea', 'SP216', 'SP216', null, '$2a$06$Wq6Gyv/jDRdlO4ynZkcMyeaQmgPjC3EPoFXX976TqIrw.HQ.67Yye', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6bbdf9d-f61f-4332-82b1-969c65ca9294', 'MTM354', 'MTM354', null, '$2a$06$Khdd7nkAqnF87wa6R83hwu.CWoPo2zCY0vkCpEfZN5GkBNsWTtxZy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6c72836-fe4f-4875-8ca0-4e86efd0c523', 'SP041', 'SP041', null, '$2a$06$/IjgKVfAViN.1rtHJHiOUuMjwxO1yeLsqM2dCegPYiYe5FdgnW1Qq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6d5564e-29f1-4a6a-b355-ae5650feb6e1', 'MTM149', 'MTM149', null, '$2a$06$qq.nVGki0nSKE4OAXkri..AZtwmfaaWPgq/Q8UpGoz.R06rhLLtoK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a6d70acd-7c67-4d34-9ea1-31cb9d462733', 'TFF144', 'TFF144', null, '$2a$06$hoKWUNzZg8K3KEKV4OA38OCppIFSx/TJ8HgR9sENzFMR7wTDx0gaq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a71ab696-0db2-4167-8628-5a764f8495c1', 'TFF013', 'TFF013', null, '$2a$06$k9wMXin1tRfymz/w/fP4iuYLSoLR2NQwY4/PUG6n2OKT7fjVeSg8e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a72b0d58-fe49-4302-8ec9-afbdbcd4163a', 'MTM198', 'MTM198', null, '$2a$06$sdAN2tqB8IOJO/Sef6gBFuntlep.hZYNt4qcq8P3FUSMR4Wjq1wJa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a72de451-de89-48c9-a367-0932507a3295', 'T226', 'T226', null, '$2a$06$blcskwi7Gqas0OZaIFqAxuCzXMpOqxeHEOAnT2Jyq5maRxWI2G9/a', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a738ee96-4ef9-4c2a-81cb-f787e34a27a9', 'SP209', 'SP209', null, '$2a$06$nKgUVxDnfI14Vk6rVrO2xOc1EggcG1d4AUm57c.iosRciMnSrtBOG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a7568bf0-2933-4f44-b821-5dba82a7eaa3', 'MTM143', 'MTM143', null, '$2a$06$TT4xfTcTT3Qe5HyWW3WW4O0iXiifnzWnnUdPpjfTHHF8.vQMNjssq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a78d8e8f-089c-45ce-bc3f-65e9b146becc', 'TAP310', 'TAP310', null, '$2a$06$bMWhSH3wFoEVaR9Cw6lUbOXi/7j4D1ykKBfOOqD/LoOB46Z/C7XRu', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:22:54.471317+00'),
  ('a7a778ab-cc4e-476e-b40c-28bd23d900f0', 'TFF096', 'TFF096', null, '$2a$06$Aeu.1EfaxaOkYReOHOHJpuEnrg.drE2/dUOUKEePt4F9dDOFCJSNC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a7bc0717-4937-454a-a14d-b6e38ebfbeac', 'SP491', 'SP491', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a7c1852b-ba52-4de4-88ad-9c183ae69400', 'SP381', 'SP381', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a7cd4954-f1ec-4e67-9301-4360043657db', 'TFF101', 'TFF101', null, '$2a$06$7rOUlXL3JhxuZTpOanIwPeYLGE.0lJbo5RjttfkHmDySlRuSuFOmW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a82e403b-3e6b-46a8-befb-d9edc127b628', 'TFF465', 'TFF465', null, '$2a$06$AGQUmBZKukWrJr/0Kkkz7OS0q1pOSnGU9YP60X.Z5Nc7yPJFj6on.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a82fb3f7-16d9-46f1-bed2-0509700c91b9', 'TFF445', 'TFF445', null, '$2a$06$skeafzPSc0wHQwI0t1hmnOQZyPkaePsB7qvIUb2ZjKoRMuq/qIjYy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a84ccae2-eb4f-49cb-9ab4-f76c485ed294', 'SP331', 'SP331', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a86bb931-a238-49c2-ac95-74b3b688af03', 'T043', 'T043', null, '$2a$06$QobToD8x854ymiUgf3npReiJEjoNEwziIhg21T1Rv4C6P.uekPp02', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a8771d21-3d83-4944-8181-1279341cd938', 'TAP012', 'TAP012', null, '$2a$06$RTdJS3JyGifnvW9mjr2JMOppzTziHZmH5QwqfDL5PxAvqTdcEjbUS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a880795a-82c8-4167-a02e-765246ac0685', 'SP348', 'SP348', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a883e941-6289-45db-8e1f-1bd10b21de36', 'T050', 'T050', null, '$2a$06$3pdj4BI2bKDs295Z3kHhLOvWeUIGvHaDtdJc6seBqruY7.2U9Ca6y', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a8c26d08-1943-4c98-b47e-3d2d71e38fb7', 'TAP230', 'TAP230', null, '$2a$06$8mwgzbqXGO7NtdNThTMWZe1kAupk2nTxcaJFuB.7RKPBqUSdqmAF6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a8e9cbd6-88be-4ff7-9e3a-1ede5f313ef9', 'SP099', 'SP099', null, '$2a$06$HdBavIcr1vRklES5fH9B3ONDl7cfTe8a5IwkBXRCajppufD7/pzDu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a8f40a86-a4bf-40a8-b5e0-1e090b3647ff', 'TFF181', 'TFF181', null, '$2a$06$2/GuMG96oHd4oy31nPGp4OoAQm685hnzuf7wL8jB0nWa7MrUr8DuC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a8ff05e5-b0ee-4d39-8689-2b4881593e24', 'TAP395', 'TAP395', null, '$2a$06$UuiFA1JNcyiqlV/dd0Xya.zjZHvy2weq5q.VJpTgbaxSaDb0eFiVe', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a9033c0b-dbe1-4fdf-af63-3a271961e694', 'TAP253', 'TAP253', null, '$2a$06$lOaKYuj85zw17/zMscPdpOObxwF.jztI8DQxn4lYQYW9qenE6GWx.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a90e9f11-7f2d-498f-9b9f-7c0b222d0479', 'TAP264', 'TAP264', null, '$2a$06$P2YKpMF7c15YxThIoSZOw.U0Ym9SGgNcbJJpZE8QWap3WxMrwDx1S', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a925293a-5bf7-4dd5-99c1-dcf6a292f21f', 'T182', 'T182', null, '$2a$06$xqsIFj/op0hKO621Aoun/.cdh4u9g79HfP80QbH1mrvmR/2iewhzy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a9369304-46ec-4e3f-a31d-089a37656df4', 'T244', 'T244', null, '$2a$06$9XL1gReTdHYILzdJAr74IejvJiPcNwBJdFgD5DJqWCYbTjA.ayb3O', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a93c25e3-5be3-4469-8040-c9d4becd6b97', 'SP257', 'SP257', null, '$2a$06$eraziwMK.qI6lPHyipCA..XZM6E/a/SZI60Uy2NLCnDr6.7c4nsge', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a9454760-f404-43f2-b90a-c5db076d0578', 'SP480', 'SP480', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a95c5e76-8036-4c9b-9c55-adad566c28b0', 'TFF476', 'TFF476', null, '$2a$06$et7Oi62U.dviyF3u1xy7KeYpVBtrSfB5WhBS5hCWSQUwMC7xu/CxS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a98c4199-9729-4fe1-8323-9bf82431b80c', 'SP378', 'SP378', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('a98cc9ca-8a20-4c22-ac88-886572cd40a0', 'SP223', 'SP223', null, '$2a$06$C7P4pAltfjwe9pc1hTQFQeI5r9bA2FW5uRxX2hzeccEMSxrZ5OI5S', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a99f0425-dc84-438c-a460-0ccec480faae', 'TAP218', 'TAP218', null, '$2a$06$vmNR8xzZabto8yC8gIeDK./Uri4FK280ut/Mv4X3oyiSDSaBWU.I2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a9af3ec4-1ce4-4f27-a13f-af46506061e8', 'TAP190', 'TAP190', null, '$2a$06$3YULcmrmiG6SQjVtCBREZ.7COeczrnuf4KHlqFXQog8A3qieYrQx2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('a9ba257e-ca86-4405-bcfc-fa93d1655aa7', 'MTM144', 'MTM144', null, '$2a$06$TCNb8TXSAa0YhzBUreihfOAOSadDiQeyoNn0ah0Fg2S6W9scBYICO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aa22b558-ec65-4197-a7f8-98a88bb4104a', 'TAP044', 'TAP044', null, '$2a$06$UaULNGq2aRVtbDOznfHKOeKjq64GJ8ICxfCABnA.Fq52hysXdRkrS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aa388413-ba5b-4186-88e0-110e4efeea23', 'TAP085', 'TAP085', null, '$2a$06$jssbtVU4KZk9.L45ceHv7e7WCNusm//lsExvutz.KKRYiuimK2nX2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aa4f44ef-e233-4f96-a466-062f1b054970', 'MTM218', 'MTM218', null, '$2a$06$xbh4RL61bYPzJRpDXTINn.7QyelG.txnXwDFd1khcR85PQoBEJvHa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aa7a0998-9f92-4e6f-bdf8-f1981e4887d8', 'MTM180', 'MTM180', null, '$2a$06$/8kPRaXOumu/nRBkeRzra.VGDH749k8Qex9vT9XBlfKhlcg9MBBqu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aa8f2dab-021e-4771-9d93-0cde9d0b9515', 'TFF239', 'TFF239', null, '$2a$06$aMv7BN6NrwgsoNkopdjD0.U.YXZwu9hsNhWpAO40YOuWBKp35.dGa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aace4675-94ab-48b9-bed5-34a7b3b77ab4', 'SP499', 'SP499', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ab00f4f8-b275-4955-9149-c367dc731007', 'TAP086', 'TAP086', null, '$2a$06$QFvBcHZVg0fcr.x48MddcOmyrInKTFw36vQnGxb1gOpZ5mT/75jxK', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab06116a-587b-44a0-b22b-e1b8590b622f', 'SP143', 'SP143', null, '$2a$06$ZTPcNSKRiplrX1PS0vq3cuId5Esimo48Kjk6y7uFPbnxF3beQr1hi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab2f3324-5055-408a-9a4a-9e5e30bda262', 'MTM181', 'MTM181', null, '$2a$06$qwGGZZ1EZJ/VLgE9eChC..nS/Hb8eKJwU/47FDduHtI34Mdv0J2cy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab4cccf0-dc30-42d4-8de6-5fc234b73056', 'SP164', 'SP164', null, '$2a$06$3mHLYbM/gYeB8k618hZAZesXkSoa2iaVe4ZVwBDOd3acri.3Dzy5e', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab5f7272-98dc-418c-b0d9-ca6ee300724d', 'SP105', 'SP105', null, '$2a$06$L8h.R0jUnxda9o5OfwpzNe3mzPCANe8c9oY/Ei5h1xm/ydMmYNIcW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab866c3c-7775-419d-bdb6-865862567833', 'T187', 'T187', null, '$2a$06$N7o1mTP15Z1W33ZCSUkk6uIZklUYI64QXlIkgwpFfd3UO7nt3snvu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ab8b94de-8af6-4820-b239-f18b0407fad8', 'TAP003', 'TAP003', 'https://elevaterealtyinfo.com', '$2a$06$svHteO70/4hAKgGK1FOZRul8MFpBZWvR0LOo1MjHZ.ta3/2yyZq1m', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 10:27:01.18404+00'),
  ('abc3e4ce-3c73-4138-81bf-4a621e02fe67', 'TFF011', 'TFF011', null, '$2a$06$klv9EszxcCJxs4/UidK4J.Ek0ImYqi0mU467AblxBEry2rKQnwNca', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('abd12cd4-37b3-4939-9bf2-af89fe7d453d', 'TFF218', 'TFF218', null, '$2a$06$JCuYN5hDT7ak7Z1I86jlP.HMrGA0NQZcnD4r74eo.z4496Lsx3NBu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('abf0ecd5-c24b-4e38-b7e3-66804637074b', 'TAP287', 'TAP287', null, '$2a$06$iaXdoRHcr2CJ4gEKBCmdXOUnlQgUr5MMwAYnXs.GKaMwBV0s9iT2y', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ac203cd5-0053-46f5-b34d-c6998b5c0e3b', 'MTM126', 'MTM126', null, '$2a$06$JuQktuKTvKJ2CEFVIjlNRegnBAWlZjf5rexZuJznYarTmbqhGuls2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ac744448-0524-4d6f-bc4e-ce1eadfcf582', 'TAP065', 'TAP065', null, '$2a$06$gMMK8Sj59wt1hmgi1/PB8.E6CHJuJZB2Rpcowe3OGHMA71TTiKGdy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ac90eb43-24ff-4cff-bdf7-73c6d004e7ba', 'TAP050', 'TAP050', null, '$2a$06$IPprrv7dSvBLiPXu6Ms5H.YEPWF7CwkG9npOrqs1UNUwUPANHUEVC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('acee97c7-2f35-4e45-8291-1f5889323452', 'TAP319', 'TAP319', null, '$2a$06$AzthENJAz/LvbjxiH0lBTew/DJuxtxYOvo3BIAkYgTuxm8ltQsJWa', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('acfd1ccc-c1e1-4a14-897b-ccbbdcc4e120', 'T261', 'T261', null, '$2a$06$tBAYlcJA7uImjZIyMWLM.ec0xsI9jHWh1hw2SvuG2q3B0kvnjKe4q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ad0d8e92-0782-415a-9934-ba14f14d95a8', 'SP422', 'SP422', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ad43ede8-1883-461f-85ce-03d439587dff', 'TFF059', 'TFF059', null, '$2a$06$mBufK86qBfKMJS63Sk/DU.gPDYCTiikbc9sJdPAmEPcwtGyL7HBFS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ad595d80-29b4-4c83-b6ef-05fed97af7b2', 'TFF364', 'TFF364', null, '$2a$06$fAjULlkVvcYVIqOC2W09H.MAMyDmHCQazYZ/pSFi0//iKL8j9y6Ha', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ad5e8531-5afb-481d-ab79-9e507ce3b55f', 'MTM155', 'MTM155', null, '$2a$06$HOoycSJ5gTGp6m.oBpzIpukqF8A70rQtykzw3piZfdayt5Nfp.3A6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ad7955d3-d837-455c-84d7-a01561f22e98', 'T142', 'T142', null, '$2a$06$Wbz.oJlCCEKyc0by7yRk/u8qsPynLY4UOGK0h1P674v5jCWvXX/3O', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ad8097cb-a9e5-4221-8865-3ba94f3c494c', 'MTM440', 'MTM440', null, '$2a$06$7g9elVIqarVEEvwNhKP9Befb7Q8UVWMfyjH2Y9aOIA7HcYPcHlaJi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('adb7d40c-4964-41ff-b113-dd2cd1401685', 'T122', 'T122', null, '$2a$06$qXrUjqsySGuqROYxFjRcI.IpSNMzaNBggdrV6Oj1ntMNvE4Opau6C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ade8ea8d-e9da-433e-b85f-33402810448a', 'T052', 'T052', null, '$2a$06$W9mMZglRsoXajEDdPQ/Sf.5wihEUOoKlpJbsg4lp0aHQYvF/jxvjO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ae0b23d8-baf2-4b28-8136-18c5e4d5298d', 'T269', 'T269', null, '$2a$06$65X5fREp3LLGMEbkcrunPOcK4skgGxgYtZCod7rjV30jKBVUnSDgm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ae19d22a-c70a-424e-928f-732bae16b192', 'SP071', 'SP071', null, '$2a$06$7YaMSuFYR.yl3cPjeY4A0evN/XKeqSgj.46r1i3BxSrszAT9R5Nbm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ae1a38a9-66bf-4fbf-9cc7-f33fd5fb4669', 'MTM431', 'MTM431', null, '$2a$06$4eqjvBsuVGNspMEw5VN58uVmFwF.KTw6Z8faK.1YXqCw1qEvejyjq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ae52f223-bd56-494b-b8db-ac8cd01c3ee5', 'SP496', 'SP496', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ae8485df-5864-4441-b3ec-e9ac35bbd366', 'MTM442', 'MTM442', null, '$2a$06$Ps5AzF/GsT2lnDkPrMBm5eOwKQTPTxZ7SByt7s8qB.KNHTeJTM29q', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ae9dc9e4-1646-4c95-a851-cac79fde8362', 'TFF030', 'TFF030', null, '$2a$06$U0eIcYIsJnDnXv/sM2FFe.sJDmvrlxz.aejni0EOSFoMuHmHSdj5C', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aea0dab7-a01a-4051-a1ed-952276d6d9ee', 'SP153', 'SP153', null, '$2a$06$A2Dr8epm2QoA7AwiosZJWOLGrvgEFOHsMa9uf.0vD1p9EHuW6RvAK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('aeaffba4-bf41-469c-9999-4644968137e1', 'TFF018', 'TFF018', null, '$2a$06$thtAM.nhBWJMIqorCfjxJePFnr3ew5AfM2ncWK8VjsShpZpBTRf4m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('aec02df5-9eeb-44a6-a782-1770f661aa8f', 'MTM293', 'MTM293', null, '$2a$06$mEY5c91q5h82kJPF7pUroOjCp.GcOEHO6ih5cAjOUk0hQP3I9hh9K', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af3871c9-682d-4314-9f6b-5befc14a98df', 'SP160', 'SP160', null, '$2a$06$49LGFMvzDuNsbMaL84L0b.XVH8pRFq5G7f7ejpGCissoA.YS4IeiC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af3a43ac-9f6b-4d87-9b41-f68069adb5ae', 'TFF412', 'TFF412', null, '$2a$06$vcxEwACsV6Vb86nkxcn5Cecol2at0nJL7dOGivLbyqtNYxoN.0BRW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af56623e-917d-432b-a96c-312b2b4c56df', 'TF07', 'TF07', null, '$2a$06$OcJhoiv3oi/8UcKRWFOhu.MX3ehNTSowNRrnTuJ9gQR63CYxdmXH.', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af682e27-397d-4041-bec0-7a93e16113c7', 'MTM177', 'MTM177', null, '$2a$06$w4XgoSplPr1lplpJmGhI2.y3dc656prXJg3Fwgx/jpYyWTFvlj09m', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af68c7c3-9a8c-4992-af07-693847c2e1f0', 'TFF051', 'TFF051', null, '$2a$06$ujx3gh3F.9T42zRnJe8Iy.08EXhkYYGTWCSrKCPciuSNRWahe.gAe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af68faaf-8a29-422d-a81f-8eb947d19314', 'T116', 'T116', null, '$2a$06$sC/Eec.b9gDGHqw/300TJO5ATwMYQm14Du7hKPqNBR8Z53FI3A.NS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af7c6e5b-9b4c-4e11-99c1-5df368e9f610', 'T218', 'T218', null, '$2a$06$2w2QLQZi8L7QhtqBtO6kSeQDF/xGST4rjzF/YSZPDePcZpBwrzUwm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af8a5f1b-8d50-4a7e-bf4c-5fd167d7aed3', 'T247', 'T247', null, '$2a$06$YXtlewRiZELMAYkALpBw9ehDZIQhsCKa39HsGqLOUjI5cqeW1HIYy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('af9a69d1-715c-4df8-b2bd-ce1c326e35d5', 'TFF383', 'TFF383', null, '$2a$06$dCRxotyTu5NNUn220ShMDOsGj7TCZf243h4caeyOS65/jO0r3bNW2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('afae8107-f7ea-4583-bf2a-165d8f372d2a', 'TAP168', 'TAP168', 'https://thefunzotf.netlify.app/', '$2a$06$eEBkUqdflrWA0AoBhYSgSOK8X58o/umW3414o7mgQ8g./d2MNbIg2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:21:37.306016+00'),
  ('afcd38e8-d074-4656-85c9-371d08e541f7', 'TFF451', 'TFF451', null, '$2a$06$EJewycgLWU4Vz2V91NevhOAoN2IafM5HKk73k0m.Zt3r.6cK0.Wl2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('afe562d3-5aef-4a38-b689-13d68875560f', 'MTM308', 'MTM308', null, '$2a$06$vXTzo1tx2Pq2JVHO88cu3u4l6h7nSf1A8E5pV/gvHlDqFEoLVy0Ra', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('afff21fd-8f19-4fd8-9751-2702271eda69', 'SP340', 'SP340', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b008560e-624c-43be-b3c3-6e002bfdff7c', 'MTM135', 'MTM135', null, '$2a$06$gAMAh00skcteqwONHo3TSuewo7ytr74dDrIcyZvbWNZNgD1XQFZsK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b01f5b63-1101-4b66-a3ac-aa07914d46a5', 'SP158', 'SP158', null, '$2a$06$C/ibyY6HD8kPS3Alv4oa8esepp80k2LxJf9I.dtg36nAuKvD/u5Vm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b0425597-bbe4-4bec-bc38-78a52b9f19fd', 'TFF236', 'TFF236', null, '$2a$06$sigQI8AktC7YpN.rlF8jnOuKhBpFyoBzTEv/WvA6C5f0xAfdXEWhK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b095f588-2a66-408e-88a0-62e8ab9fa9bc', 'TAP074', 'TAP074', null, '$2a$06$wSxo.4hzbBVGkhFT42w/eOWhoK.H4ubpp09yGYkIdFxqILbe/JUzm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b096a304-3df9-4f7a-9a28-292050936fc4', 'TAP178', 'TAP178', null, '$2a$06$Y13GerLuytOthsF6bkLgyeJdNy6tdtgP2fLQKeH0K.9tyARyn9XQe', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b0debc30-2279-4f14-b6c2-1008b1a24118', 'TFF390', 'TFF390', null, '$2a$06$xs6eD5CnhtROAVcgzUUIM.NjYKXwMECWNZVkykK0xXFl0ZRrV5.Te', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b0e0574d-89e5-4695-a474-2d5ae450d8ee', 'T171', 'T171', null, '$2a$06$NGxSk1zZTQrvXK2nENXx2eV8339nEk5D6eU8OAxWZSqvAWhc/G2PK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b0fa2734-d250-4e07-9ead-096682b0768f', 'TAP011', 'TAP011', null, '$2a$06$aq/MurgG3vZ2fsMhDkPbT.93047ZqSNigZm0Reu3yiDhT.aj9g11S', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b10deeea-a767-490e-944f-951e56127460', 'SP307', 'SP307', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b114a58a-6cad-4af0-afc2-18ec5ef41804', 'SP199', 'SP199', null, '$2a$06$UGOye/1DphrpePyHKNJ7auAsvK7/cSqTuK8fAjtZGpjD6hyVqFNdi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b11b0b7c-ea08-47b5-ab21-3ed950c2ae26', 'TAP140', 'TAP140', null, '$2a$06$HjXCePTHX23jr/w5jSHWbu7chHpNILQx1K979grzpRwWCRuDxSh1m', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b125e7af-3695-45f8-9bc8-31dd28c1535b', 'SP238', 'SP238', null, '$2a$06$aub3urxJ9N14CqBXTOFaSupDW285.WL1AkifCWplrxeTzBTSIsdni', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b1469816-17a2-4c61-b48d-b7823c00ca89', 'T150', 'T150', null, '$2a$06$zTRYT.E.M0y8eBixU9dxi.D6d8VBQfPDz4Vk1PZ5OFntNiS1LO7fm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b18ab87d-93df-4fd8-a598-04f32f7b14b6', 'TFF384', 'TFF384', null, '$2a$06$sWxd95L9UTkLWPh2z8zSn.IOuW06fqYwrweTpz8CEWi7h9MOrSrFm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b1cf0c3f-29c2-4883-9f3a-92b25dbdaf3a', 'SP095', 'SP095', null, '$2a$06$2Kh5W5pvqGwSRFzFmOiW8.oqRfXFTUPy8QO0zrFClpNvOJBt/MUSi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b1d74698-1871-412c-be83-4fc5ebd80782', 'MTM213', 'MTM213', null, '$2a$06$Qd6XNur7jXyZhOgIABRhYu4UuIsUoHjkUCY8/8YECbGUP.uytIuiG', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b1f201f3-3474-4678-8fca-bcc1a15e4d0d', 'MTM324', 'MTM324', null, '$2a$06$lHUw6qI4VJQwAx72LIvGVu7u2uqSk55ySKCMpTHIiFmbkez3Sdke.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b1ff7c97-5d83-45aa-a70a-c3078a0d1f23', 'TAP240', 'TAP240', null, '$2a$06$H9LXrw.93fPuoA8LcQH0Q.O9n00BW4PDkL4xRvqmHgMi.6CgwlRxC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b201e016-07ac-4fd0-8c59-807da431c350', 'TFF292', 'TFF292', null, '$2a$06$IrygYT4PbogCvRLgc7N3ve0nHa0ryQIMzLRwvwuo2dGsX4fmM/D4i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b2550f4b-d357-4487-871e-85b65e260b7f', 'MTM133', 'MTM133', null, '$2a$06$R7ZCo12Zuq./dU2b0oqP2eyy3qWn/CuwHp/Z9zElBUQHcyKyXMguC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b27e62fa-7c06-44b9-810a-18fec05b40d8', 'MTM412', 'MTM412', null, '$2a$06$1jWmA/aNuj8CD9VsqJ/YmuXmqvDfPAneYm7fJbZoDQRwQY0TiX9Rm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b299bcac-1311-4858-a4a6-d50dda397c7b', 'MTM393', 'MTM393', null, '$2a$06$s2VQFf4TLXc7ZHzx4Dw7DeMaCS9cnFzMm.2vr.48WUvTjcHumqlIS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b2a36cdd-764f-4b76-a446-e489bdaf3a3d', 'TFF474', 'TFF474', null, '$2a$06$a7Lmon7eOo1jj4RfUtOcLeZrsqckfVRQQJ4Q3TnlN9Z2eWc3GNLzu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b2b77e67-38a7-4561-bce8-492658f9fd95', 'SP241', 'SP241', null, '$2a$06$i3MKs8DINjNU/oq8jD6i9.6nGE/ujaJntPSWbarl/S9AwtehZFiva', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b2bb3210-e57d-40c4-8f85-5d3474c869c5', 'TAP377', 'TAP377', null, '$2a$06$26ArbSSIYDOoMuhmECsJAOxz6vwwvo.LGeSpzwwUJbzhB/U53MYq2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b2dd3789-4413-4f93-9687-106fcd901da4', 'MTM247', 'MTM247', null, '$2a$06$UaElo8qd4aoF8JTiXfF0Euu/X7yAf45RJxpVz6RwClBOVrfJ79aOi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b34509b8-88a7-4c91-9081-dd57cba1a68a', 'TFF021', 'TFF021', null, '$2a$06$Hs/cnj6SfitjcB9GnaDEpu.cJm05EjdrIpzV/EpPxyNy8lP9D0K6a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b3458274-e5a5-4a06-8a36-0f0e2957ec95', 'TAP222', 'TAP222', null, '$2a$06$PI/QYQvIdvszemrLY9Ss/e2ccRFb2quYZ2ZGXHkjfBfz6EsxoB6Y6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b3502167-eb97-4044-985d-6966f3c67832', 'MTM372', 'MTM372', null, '$2a$06$Ti1reXwj9LP4n1I6AlRC7u2CRTZurQ9QOBC2lHtVbDq7LE1T/y3A.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b3eea815-3af5-451d-81e3-a15d72511716', 'T049', 'T049', null, '$2a$06$xxD24A7QyoOssA8yPppuGeCcz7aRAV6PKwN6tCk4g6pKJEPvjvS8C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b42c2771-d64b-4c8b-8b26-f11e2937c4fa', 'TFF362', 'TFF362', null, '$2a$06$Po4Z8uv/xzBrWuGpGDUHsOwnrKRlIKoD/NJFodXCte0BCfL49rM6y', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b439d913-71c7-42ea-9543-ab54222c27b3', 'T093', 'T093', null, '$2a$06$tS5GIcT2NANA.jSmHyzAduX6QPJQUztElm.kizD4exMkDGsoONYLy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b4b5bebf-329c-472f-b484-4b9b55e744c9', 'SP120', 'SP120', null, '$2a$06$NPXslz5uFbYzSmh9rK6rWuIMorLLCrAOHajMzYecZnCUI48Ji89u2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b4c98ea3-32d1-4c88-b44c-6664424fb041', 'SP359', 'SP359', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b4d10cc8-ca5b-413c-b127-d9b3b561506f', 'TFF290', 'TFF290', null, '$2a$06$fwCRcll1dNHCBYPCLAp9gulmMzwBa8ZlqyAjqT69nU/7pULHZc3AS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b4dc8376-ac25-40dd-b1a4-f363a6142cb7', 'MTM182', 'MTM182', null, '$2a$06$2NO62pW6z068CVDBomdVJusMsO7NC9vYocxycnAiWtsh2bASn1s/u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b4ed510b-8f85-440e-81b3-a9d3de750911', 'MTM351', 'MTM351', null, '$2a$06$6qD8p1WEaQbwMbEUOYZ/S.zAefVh34l0tCmTVgDFCxe7umbOrIHP2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b4f71a8a-5fc8-471b-aff6-9aa234f08d94', 'MTM249', 'MTM249', null, '$2a$06$ZYJfLNLwoxYWIS52ZDqqb.9SmUbQJGzew04xBdpyHMV3WWFwb5jjy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b502a3ff-77ec-444f-b108-30429fc5fa68', 'SP031', 'SP031', null, '$2a$06$2vPSN6uRZEQZEumzFwhBietCPbLucX2Q6vhMFCA/sjkBR8j/tbsny', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b525caaa-793e-4c3b-9b3c-a5edb5db9895', 'T054', 'T054', null, '$2a$06$11sOBRrC9eXkQZFVgx6Youg.iFXOzz3bgDRSgEtvoYHS9CDxnj/z6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b54d1939-a667-4f49-9dc6-e86bf43de293', 'MTM390', 'MTM390', null, '$2a$06$2IYCo4kSR7LA7jlUjwF4w.lUH1tpDQ1.A/G2Dn7BK/bBmvAgeZ0hK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b556797b-7ca3-4ec9-9e0b-bd877bcea0fe', 'TFF267', 'TFF267', null, '$2a$06$LshPqqfnJR4bMG08crXijOXgcF2MPs3vDdtTeZm1Yu/hGwJnWrama', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b57c3682-1914-4853-b313-3d21f981ebe0', 'SP017', 'SP017', null, '$2a$06$gr4vQ2..CGT470.BaVVPXev5JtQSt6xRXd9lZgXrWByVF9TcbSrOO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b5949625-eb8d-4386-a104-e475a65f0053', 'TAP231', 'TAP231', 'https://search.google.com/local/writereview?placeid=ChIJ5xh458iVDzkRzPtS7PO8grc', '$2a$06$gLDpaaWBsMUsAfUr7eYbx.APx1IFMWYOdnRavn17sXn3iy6Gh4QgW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:08:42.508191+00'),
  ('b5b1233f-3290-434f-9e98-d0ea17ead25d', 'MTM319', 'MTM319', null, '$2a$06$TG/HKjMuweUP0qj.SrGbHuebz0cHDckJQTYzKhDopc95hggGMQABa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b5b12e9c-d204-40aa-8704-a7f7e3c8fbf0', 'MTM352', 'MTM352', null, '$2a$06$lpesKRPNNbt/.m0QnuBGk.C8SuNWjg4jRuwpZrmHytFJwhm1P0ocK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b5baf48f-fcfe-45f9-81c5-34e8d1be512f', 'TFF361', 'TFF361', null, '$2a$06$UZaQtDW8mier9pEmjbobR.P/DcRtjNq0yITHYnJA9c8ilx6/t6ET6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b5f85570-6503-408e-a206-6f7804209a72', 'TFF037', 'TFF037', null, '$2a$06$IhWWtqhwBisQkjs.tCLNbeBGl9RiwjsO8eAhLSPdQkU7rH1wIo0FO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b627b1d4-d4a9-42c6-b7a0-70a3d3438821', 'TFF423', 'TFF423', null, '$2a$06$F53GLOdg9U16SqBxazwZjubY7GL4bPPVamGVHULPc/0K3D/BunIuW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b63b6af1-dd65-458f-a5f7-55d9b9eef4e0', 'MTM348', 'MTM348', null, '$2a$06$nMkE6nBH4qW5nmEhwg3rmeAtshGsaehmjoscqC1TS0Zpemw9tNk/O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b64e2b22-6217-403b-b660-c80bc8b18b15', 'TFF366', 'TFF366', null, '$2a$06$fICRW1D0J776v.mQPFPp9OBD.T6Pk6UPF50Ii7EwhuJH7divPWkCa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b65431a8-0ba5-436c-932e-78bd533b3396', 'SP311', 'SP311', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b663e682-9390-44d3-a273-142fac353e8e', 'MTM314', 'MTM314', null, '$2a$06$o2rdu4TikxmUNRAa7aGheuYv.TjTHLJm9K6vJwGg2qtSKLJXS8Kee', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b67977b0-79ca-48c4-b191-db17025721e8', 'TAP060', 'TAP060', null, '$2a$06$3lqHfbeROZPJtlXmqdHU9eJEISvdKtFINPema/oWve1OiceqDVrwW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b6908cd6-3454-4364-bf0b-72a08c51ea16', 'TF04', 'TF04', null, '$2a$06$QKZCAqA9CQuZMtTBKvllBe5dQD0kXNlQfi3rmdrXvhCUipdOWmxu6', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b694535a-3d86-41ea-bf03-e818cf449f83', 'T217', 'T217', null, '$2a$06$VqEFIFrt70vm2UEfgkXrQ.z52tKQ2ecRLXK7gXp2um7TVSZHobIL6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b6b6e494-17e2-4239-bc69-9c486a901b5e', 'MTM339', 'MTM339', null, '$2a$06$DdYDiKC/wsEhM1WNa/GeXOKoEUZylPycfTAVZn8tspXwiJd7t3tpu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b6c3a4d8-2184-46cb-a8d5-b967b7974530', 'SP495', 'SP495', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b6c40975-9320-4cbf-b0be-5f68b34184e9', 'TAP077', 'TAP077', null, '$2a$06$v8cpAoHuvKnUqydygSCaZujcf/XyQbwEVxrmheLUC4vaZHLBZLpmu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b6d7e3a7-3a10-4a50-911a-bd8db44f74e4', 'TFF094', 'TFF094', null, '$2a$06$UjgjVB4/grYEXR.c0e15N.FDuBF/NFe/vCtCrcFwtlDlEqj7duHva', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b6f3a536-a9bb-43a3-95ac-08edd5dac332', 'TAP182', 'TAP182', 'https://search.google.com/local/writereview?placeid=ChIJowz7NUDtDzkRgRsOk6qNoWw', '$2a$06$M8BcC5BBEPQAKDD50i9tvudCjI8v/ICvNkMrqXEdbba9bGeNocMQi', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:25:27.324617+00'),
  ('b7397bf5-c6da-4035-898a-839a6b2b7e66', 'T279', 'T279', null, '$2a$06$phbpSM9UfVHQAZzs5gJB9uWMF8gM1fIDFfDR04o78KDa4WNWDlfRW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b73ddd5d-8614-45d3-b651-2defb1556b43', 'T294', 'T294', null, '$2a$06$qhXP5fyZ6wIxw20nrk1hNONAVRTYUjd9zwCCgkxCgHil1WyLULD2e', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b77730a7-9238-4b29-866b-eb6b005b1ad2', 'MTM383', 'MTM383', null, '$2a$06$9Gn.LIdfJY3OGSxfARCYu.nc3t1OROsal02N2cDXrelvuuLkywVT6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b7960db0-ae3f-4b01-a342-54db7d719a36', 'TFF167', 'TFF167', null, '$2a$06$CSxue6hGwhBfR5hhoPSuT.StClD0X6Es4YOwibT4h4UKdRlDwS35G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b799b48b-0f62-4838-9788-67b2a182c866', 'T074', 'T074', null, '$2a$06$Cd0UcLlQoTSYKFSyRUkd9eK3kETsyc22aZPpyuhBtHq27CO1qWuCm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b7a3573d-4925-4189-a212-3f06b15f97ab', 'TFF015', 'TFF015', null, '$2a$06$n634q55hwoOkeuWgmsHI7OI54hQ.CMQG6XW9uca4rb9SF8gUBy4Ye', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b7acb67f-9928-4459-8b89-1757b8148abf', 'TAP005', 'TAP005', null, '$2a$06$xUzeeTiaZ9cdgIM4FagqCOVumExkxxfkI7.nzj1JNgJP3bpIGLfcG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b7bb2848-44fe-4ca6-8553-ca22d6134c18', 'SP177', 'SP177', null, '$2a$06$urrIZkP8u1gyTRNq6FmtB.uArXqhclg8ESes25k/47biP0eYJLfum', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b7bf758e-7187-4b4b-a584-cb2e9fde6f3d', 'SP439', 'SP439', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b81a6a13-aa46-4cae-b639-3f024aa83f51', 'SP364', 'SP364', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('b83ff44f-8c73-4ef0-a9da-75d28e553635', 'SP109', 'SP109', null, '$2a$06$FHm/sWiytWHCsgJ8hJDsluFXtPpJZn9PsqBGWLcyTXVhDv54T3BhK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b84fffae-d1d2-4308-bc31-32557b45209a', 'TAP368', 'TAP368', null, '$2a$06$k8pznQO4mrOAkq41WkYa1eqbx8lt/BQN4MuQLQWD5UCUQuMQVjUou', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b88c4d2f-b454-41fe-b96c-994b733a2406', 'T039', 'T039', null, '$2a$06$DbfiRQ1asmktbIK3XMjTL.T4.9G0ypvkvXg/4VcrtvB9nkSJFnM1m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b899c5ba-a028-4bb9-a4d0-222ee27e18fa', 'TFF192', 'TFF192', null, '$2a$06$L48Qt4ZFIlaAYDCvoyzKsu9McvT5i3zu1gglBF8XSuI0UFa1IZe0a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b8eeeded-ed15-42d0-a36f-bf84ad435f67', 'TFF202', 'TFF202', null, '$2a$06$LzI.6gypqbloUwSs3MLAAuhmp7d2ZMHGejPNngz9C./vJ5mO1iBsW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b9725fcc-8354-4319-818c-fe4f7e0d30c3', 'MTM146', 'MTM146', null, '$2a$06$TrvOQcyisWjRLLKZgdbdfuAJtPM.Jg8xZJyfLPRS0fyV.O619LKKy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b9869e7a-9962-4b58-9ff6-78af8d4a4a35', 'MTM294', 'MTM294', null, '$2a$06$mxxC01QbC9CYEYfXRjEufuOF0FrFeo/WXfYk9vdzSHDhgZhMHv0Ju', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b9f72b23-db0a-4393-b4f7-8b1e182a8c42', 'TN21', 'TN21', null, '$2a$06$h/H3sHMsBBSDuBdeYv2KsOPg7fqjhiPi2tKhKY8lg9UafMal9TEY.', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('b9fdd931-e3c3-4f11-90d2-f8343bc09667', 'SP280', 'SP280', null, '$2a$06$j7ggdo1HtDaYC49qiUg7OuXxvfjaoRbHPElkdisJHyxiLU..S2WQ6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ba224f3d-e2cf-44de-876a-fd3a195f1136', 'SP254', 'SP254', null, '$2a$06$1xUCbZtb78I4kVr8se6gqemOSOzRWkpEbUXk4bJAY6uxPYGPEkhIW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ba5b40dc-b200-40ed-ae21-80c61745abbb', 'TFF114', 'TFF114', null, '$2a$06$H7yGscKQHf5IXIKiG8rYgOg7Mfl.m26sMphzwbDQYwd.ordV0mlni', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ba960fbf-77ab-4cf9-95c6-48dd77bf32ce', 'SP274', 'SP274', null, '$2a$06$7CnyscBqZrMBF43t1Gm2ZOh2RnFdP.Nl58RuTS3xLgleSE9/OjBSi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('baa27dc1-b579-4022-bd69-d1161828e690', 'SP134', 'SP134', null, '$2a$06$ZJQlg7ZGVXm9.VxC6tNT3.j36ORVPIwggCVl.O463NFl4lYjXK6dq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bac891c3-6ee6-4315-b01f-aeb1d4ceafca', 'TAP262', 'TAP262', null, '$2a$06$G/RHzNKkNvvMVvyRwelH4OVXMOFkilvimwCHr7xFTW8iveCutGL6y', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bad64e87-ab98-45df-adde-5466ec96a65e', 'MTM201', 'MTM201', null, '$2a$06$ulsLLJrHDhg0Xo/MBQXmG.zdymr37G/FcSmYlkrMAr.DPNVTxDcfa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('baff2d83-2623-411c-b372-fa8186b0ed2c', 'TFF276', 'TFF276', null, '$2a$06$wy7Q91lVdSYMvtn2ro3N7O7nR4ZlJpnZ7.BlZAZZJgXa7yqJLvA6G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bb222bec-ad31-478d-8bcf-3a8bf9d175bf', 'MTM415', 'MTM415', null, '$2a$06$TqsE6N35qlRwOP4d5Z9pEuo2w19BehVIbEl2TdnNFl1EeodEA4M1W', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bb27c03c-a2f2-4c66-946b-bfe79f4c9f85', 'T094', 'T094', null, '$2a$06$IHqBCkFIDhS40YuEtunQROPK/LPkuCXIpHD5WQrtNXE5DUmBtKxUy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bb508530-baaf-4f14-89b2-ce2a68556f1c', 'SP330', 'SP330', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('bb6e4e6d-dc60-4c7e-b4d0-8c3f464382f5', 'SP037', 'SP037', null, '$2a$06$4ky/09sE/g.F4fTiVfmQ4e0PnH4PE3S4ZkWi7QcdExVldh3HX1yze', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bb8f9880-c3ed-4b68-9a93-97692e2635d6', 'TFF315', 'TFF315', null, '$2a$06$AmkyXqCAWb8SdbdItMcgGecpire2878Fqbv/aCVZk31J0DjjNkfIi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bb91f9ce-41de-499b-96e0-ce5c5650457a', 'SP044', 'SP044', null, '$2a$06$1TiXI/suP54Cf19bn0bSYOu/LjbThDFNVEw9KhwB67/EwleYTpbvC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bbe3c9cb-ae66-4e48-b5fd-95306430856f', 'TAP096', 'TAP096', null, '$2a$06$rn1xwhfjGn8IYaPnm7DLPutvMqKVoYxdRUNiHlwXrzHoU0fOmE/yW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bbf1d7a0-accb-4ccb-947e-5bb213cbc407', 'MTM279', 'MTM279', null, '$2a$06$2ivedtBcu.pI8J5u97CYr.4alOP3aZ4Bt5VUrQ/5ZFyUdgSIrSXWK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bc1a67d4-014a-41f0-9a0c-a218a8ac9d45', 'TAP155', 'TAP155', 'https://search.google.com/local/writereview?placeid=ChIJrcb_i37rDzkR11-dJslmcWs', '$2a$06$3egIoUstmgGZFLYt4/lbkOBpvmKcJKmYzdlzFKwuHfhz.az5dfxRm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:29:15.388065+00'),
  ('bc235a45-8617-47e3-8c75-f9bf34feaea7', 'TFF271', 'TFF271', null, '$2a$06$OEvrO2RESBCQ89Xwoj74gOHGP23CVP6trwo7TZaQYwaFLyntkSj2O', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bc3bc2c6-4730-43ec-b812-f9c1c6dacea3', 'TFF281', 'TFF281', null, '$2a$06$fawJcnAnbZWkWcMKiLXJ7eFoJvpvRuXitMCi0f25Imvoh4S/VGdGq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bc5423b2-e680-4842-9e95-9f198b346fc3', 'TFF164', 'TFF164', null, '$2a$06$fal1N0T8HkfPVYLGArozh.NOxyCeOJL1xJfM1RW09n.djNPRkkufe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bc5e69cf-603e-4bc8-b4cd-ca9d4f8f62d1', 'SP320', 'SP320', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('bc65787f-ac20-4dd8-ab94-f8aa724ba3a3', 'TFF162', 'TFF162', null, '$2a$06$MQkgKmHitXUUPLa.csof4.NOaOX88DtpRKNqzlaPlBvU1W/R73Gr6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bcce5024-8926-4187-861e-bc31f07d8ec3', 'T183', 'T183', null, '$2a$06$1BhkrKST6utRU7xm3oRm4ei6QPdNHrs4czBCxfIOjy.2JQVcLpjpm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bcd19b9e-9cc3-42c1-923a-913d9790f303', 'TAP075', 'TAP075', null, '$2a$06$x5QZNQZtfzriD.FzwhIRROT797BIADLM83xRt8WKQEcbeVkDGZxP2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bd00f5c9-b6b8-4d3a-a3c8-6d2ed40580d9', 'SP075', 'SP075', null, '$2a$06$2uQoTXoabiKcvGes3XwMq...tgeFhWiybLsroGBomhAMy5y.h3ete', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bd0d262d-705a-4235-ae89-bfe83f3dd328', 'SP170', 'SP170', null, '$2a$06$V9WLpAD86gpNuMNX.Lz5z.U9vU9g5FTTGIpVAxPHhTjEH70rLfEk.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bd0ee755-6d87-4fd2-9d10-77c916696972', 'MTM284', 'MTM284', null, '$2a$06$Nn6MyaEgYkCa3IAlfuDeteGYtwqhPzNt9bg/oPOR94Ob3mpWrqFUe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bd5e6877-f8c4-4ccf-a41a-8d5f4b26f561', 'TFF299', 'TFF299', null, '$2a$06$fdA7d6qZ3lk7lOAuLt9lA.JvylTTUjUakVPWs2QjigQt3m6vjk7qS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bda55568-f91c-4c95-a244-47468fa4309c', 'T104', 'T104', null, '$2a$06$7eirqqnMNVZsihJuwAclKeGc6RUlmtJm5fg1mhyB6YhHORXI6foy2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bdb9812c-e049-4072-995c-d482082e6ec7', 'TAP223', 'TAP223', null, '$2a$06$c4ME7Qc0yZ/rq6wxbYNZG.6z4cnqN5g8WR7nlg.nNRzVdqvVmcOf6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bdbfc113-26fe-4381-8550-64a64a84ce61', 'SP076', 'SP076', null, '$2a$06$yCzJwZ26h0dmEyRtst80xOhdmxrJHr/PreTxEFjWfS2evhqgjzIuO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bdccda58-bb5d-4c97-a46a-64742ede7d27', 'TFF211', 'TFF211', null, '$2a$06$Ueus8s5Ml6IjKW4pRvgpC.uZZlbwKizY5dmrbq5YpcFKHNKu2r/wi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bdeb9ebd-5a5a-4664-8fef-1c2f01a764fb', 'SP315', 'SP315', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('bdec0a7f-e8ef-4560-8f70-361232d0f651', 'T284', 'T284', null, '$2a$06$4h31lhAzo/sfDTWqLr6yk.3Hutho.MnjJrPutU8YEMPm2xtp.Sa2K', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bdf7ac81-832e-4413-b581-79aaf432cd66', 'TAP082', 'TAP082', null, '$2a$06$FYmqz/wFFRk3FtytzLASiexgSMsJeK2cPx2L1pdBRMOjm851xp1di', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be30124a-3188-4ebf-8455-1bc95c6d164e', 'SP069', 'SP069', null, '$2a$06$IH8joftvhu4oLqrD0xPMg.strK3oaNK7KfN/3Ng.BEorARv.pef9W', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be328f65-bf7a-4d60-9fd0-2f0b5d1438fc', 'SP060', 'SP060', null, '$2a$06$YGpfFlGt2S5ZYGK8azWn.uvYDJqR0Q7iytkQppiF97crh7bMMnB0G', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be5121e5-8cb5-477d-a927-925989bb82c0', 'T113', 'T113', null, '$2a$06$tD5EHSSBgEKX3VwPv3szw.6eKxIm3LCeONpPu2bwjDBLqpT/1dfd.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be5149f3-b74e-44bf-aa68-af352164be59', 'TAP049', 'TAP049', null, '$2a$06$tXXFYU6wqBUuygLDWogrXOGNtb1qR0JkKkjlA4ifQ5Cqm702Xc2WS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be590648-1f0b-4d30-8fec-b56107e61d03', 'SP396', 'SP396', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('be5db549-2a14-4baa-90ad-7666c9608492', 'SP385', 'SP385', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('be600459-af51-4252-bc22-1614007bc865', 'TFF359', 'TFF359', null, '$2a$06$OhSP2qMYm4d9AjD/CE9D1u8BVx8dublznHZYXyDa/BsozPJ78TBBy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('be69bd24-4e3a-428a-b315-129eabb7f770', 'MTM278', 'MTM278', null, '$2a$06$NXOz1G7BY1880y9peMRIj.JVxnxk48BWBtlo.DSxkmLyYuCi5EYg.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bed78950-0efe-4fc2-865d-0bbc203a6211', 'SP203', 'SP203', null, '$2a$06$G8zX1zbbJw3ddMKxD0Kl9ul7k0eA2DXJu./bVdfQGRudDdx9tS/BW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bee2ba3c-3ea6-4781-ad93-99e6d625f218', 'T053', 'T053', null, '$2a$06$vVUCbssu2iqdhtarzqUI8uqC8Fil0KqpB5pkyEG26B5Dx6cG08iSG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bf466e35-06ec-4a15-aea8-4bcc9d7e5f11', 'TAP318', 'TAP318', null, '$2a$06$OP9CA4./RoG8.jjxNqYecOkmnlciq9WnQ74sSF2xoLBbkj9FolWN6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bf60a738-9e0e-46dc-95c9-9dc32243b018', 'SP233', 'SP233', null, '$2a$06$1HkGi.H4q1kr9HGFca983uoMdlIelLbHepjkPUfS6wILkHL31.tJ2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('bf7be264-9b41-4b0c-a3da-98176fbe4a28', 'TFF245', 'TFF245', null, '$2a$06$5NQaLnhs8piUkrBtl7QUXeJuhZ3HV3ZODjlz/AcwGObkSuC/CohV6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c087bbda-58e1-447a-a486-98681d171590', 'SP068', 'SP068', null, '$2a$06$t6J/yY3fJSYSV19lRjTPtedwFgfofuwsq6MBguCBnRlWXBflU9UrS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c08b25fc-ae71-4e7a-a352-0c2ee6d1f926', 'T036', 'T036', null, '$2a$06$YaMl/9W5zqqPqtrjDZ9L/ee0iJ33H5sYeQYlu2qmX3aaqXdXk8oa2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c08f9ef5-2389-4346-8ef2-0b6d1e5647d3', 'T035', 'T035', null, '$2a$06$h5aV6DMJLZEgvn5UWZoxtuF9g86e9lzf09yTzDNOpuNNAH1PXkb0a', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c09a1c49-2d80-4ff0-9408-d950ebd79eb8', 'SP032', 'SP032', null, '$2a$06$VEfRq1CrNsvRe8alkaIPOO7OIJ2avOXTRQGwUkZdVMRwuXHq9NeJ6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c0b71308-1d9c-47d1-b548-44c62729bbc5', 'TFF305', 'TFF305', null, '$2a$06$uxdZIE9x2yXEmsz77PJypeektpgIrSggf0.TR0qjpeHz25IypTlz6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c11256ce-c507-4918-a03f-d1b66095b458', 'T196', 'T196', null, '$2a$06$VYCoIPV2q9NxYsuuuiPv3.CGiAFb15RQmnOX0rfYctWmcpH9OqXk6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1552166-e446-4c11-813c-f45b082819e0', 'TAP366', 'TAP366', null, '$2a$06$UP7iaeT3FRopDBZUr25ftOvDOdxaKz9mJpxD2v59lExrFVG0wE/tO', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c16ec277-901e-465a-baf8-fd3c933601fd', 'TAP252', 'TAP252', null, '$2a$06$HV1Fwu7zagBH7txxQV/g6.ljLUZwAVVCUyFChwMBqkCEFgH6.n6AG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c17b94d7-00f1-40cd-8319-6d49d485683b', 'T117', 'T117', null, '$2a$06$5sfleGcJHlSFgxaZL85VXOBe5g9BT65kVHs/5ulKzrNbel85y20iO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c18e122d-cb59-49d6-bffa-4298fa02f128', 'TFF017', 'TFF017', null, '$2a$06$bRxwj1KKYqK259c.SfD/.OjZ3SnCGRQ9dYk7EXB7bx0iOu.W2QapS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1bf5111-dd08-4026-ab20-40a20a70a97e', 'SP121', 'SP121', null, '$2a$06$DXjdhslQukEIEtgDTlu.F.B0MDat3TnpgctMbxwN/SXqSc6ufSiVe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1d97a43-3d4b-4228-a7ab-07d43949d11a', 'T120', 'T120', null, '$2a$06$qfcCmg3gMZAvSBdySclCHOdyT2pTtc/C6Etc.ARrcc.wGzPXGhUlO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1e2df87-c94c-4812-a087-3955c12d0038', 'T235', 'T235', null, '$2a$06$gSwu45pdSVFC5CLLcN5peuPMGNNTwNbuOX9WeFaa.EJCPgkSOrHOa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1e61522-85ff-4137-9d24-b6467c812e0e', 'MTM395', 'MTM395', null, '$2a$06$ALx8PXVa2Y2o5dqZt0deKeJn4wYR/MrFzk.c7Vz.qc1Ib5pXqLAC.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c1fad088-9a68-4d74-b61e-b809a09c14f2', 'MTM258', 'MTM258', null, '$2a$06$acU19R6Joi1npU8TSMHFkOYslL8gqsTlK8Wndsvx.PsTNDVe7sNmy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c20ebe32-0f0b-42c3-b18b-2d2a2ab98eb1', 'T088', 'T088', null, '$2a$06$PKrX7y2C/GLElIIdQXqRke8l5IbIeVi32aK7aG5tVvdpqCLs6/LqO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c2215c3d-e6e0-412e-adce-ea372d891d4a', 'T112', 'T112', null, '$2a$06$XlRbl4BIR4a9f0baojh3GeHoSwPvwnGfFlu5by0k4B8q8GWzhwwRi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c22a84e8-0f61-460b-98c7-33859ae8088e', 'TFF498', 'TFF498', null, '$2a$06$21SfcuriTd1/R734qBc5d.qiibFSejyrkg4CFN6ZocM4N9iIcPYHG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c22ac45d-1716-43a5-8eb4-a60e3ae9e189', 'TFF306', 'TFF306', null, '$2a$06$Vk3oPMSOfRp7RtwlCkb.LODiyMaIeu3oPfxRUWRlDQgA7IYSuaB5K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c24693a0-7fad-4ee0-8a29-bbdef4021498', 'T091', 'T091', null, '$2a$06$MhepvO9LYl/UuQGryX2Xmebl3SfZ1fWWf/Gb2o0tP97BQKRopQzaC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c24fef3a-379a-44dc-a9d9-08787ef735c5', 'TAP071', 'TAP071', null, '$2a$06$bRZH/z5Y5OOBW3wEsh//TekzTjv7WhS.BErBDErF6eC99CZPFArly', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c29552e3-58f3-4a35-afb5-cc31bc27c8bc', 'TN05', 'TN05', null, '$2a$06$7kTyIFVQMXg9ktCQJkqb7erexPygp55DB/F.7qpcWYTaGpxDc8Ktq', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c2bbca59-41e9-4632-8edf-e0c681d7b576', 'TFF084', 'TFF084', null, '$2a$06$ZKd978kfh/5uQXR/40Bp5OaFOlNDNmoYgxjntfFvC8e24f4Y1Qlne', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c2c2e5dd-a2ce-4f87-a26a-4a2361e70e81', 'TFF072', 'TFF072', null, '$2a$06$XgQ8LQ6WbNRE55txZsiuYODFdouzz9nNGTueEnXAH0FNaTpLGGTi2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c339b30a-37a9-4ccd-a61d-9780c5f7f8a4', 'MTM221', 'MTM221', null, '$2a$06$WpqQyguh/iYfeieCg8qC3OzdPbjT.sGaV9zbRO4ehy2XKMjjv/txC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c3546788-b987-4c06-bea5-78bc5944c95f', 'TF02', 'TF02', null, '$2a$06$Tl7RoZuxDacYNOE8NU1Z7OokapQieThmg2JeqshPJ7yC0pb8eCjMK', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c359ed0e-606f-44f4-954a-fa15937221fc', 'SP038', 'SP038', null, '$2a$06$rRwG.5UzxVgl/cQf/BRyXu2i0lZzlUAt4yWUZ5X.JxtHB80p2lbSq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c3b2becb-fabd-4137-acbb-0aeb1f29e77d', 'TAP179', 'TAP179', null, '$2a$06$zG0XboFomOwLGeBLTM17we42Xmes0cmqV0DPDS17m0IwVK9b5b4nu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c3d2aa31-73a1-45a0-984b-b26fe04847e1', 'TAP274', 'TAP274', null, '$2a$06$PuN9z7dQPMW5HyCw2Mq9peRL5kf1w/u/OZP7TuY3zv1APLh.x74qm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c40162e6-d84b-4988-b8a3-aa12442f301a', 'TAP062', 'TAP062', null, '$2a$06$oRv4Lw/CK/juDB9jSjO6s.r1HhEkv1IQQfGDSweGLE8v93R8TaNuu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4079d76-4124-4325-b280-df1a2ceb784f', 'SP047', 'SP047', null, '$2a$06$/saYk2HPpQUmlOARsiCj6OQYlhPwXyaNUWbfq6CYsd5jGZ.3zt9SO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4155bab-d280-4236-96a3-701e75325de1', 'TFF093', 'TFF093', null, '$2a$06$dbDCSRluV9K9WiDECN0psOmMF7jcd2gIemFs/7q/H2gISP2mFP2dS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4159929-b82e-4323-b222-00c290e9608b', 'T103', 'T103', null, '$2a$06$k/xOagPXjITrXF52XpFBhODAUpMFR.HVOkhhuDCabV9/bP8lwNqPy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4163de8-0f1c-444b-8b09-6018e7ac311f', 'TFF457', 'TFF457', null, '$2a$06$ksBeqE8ymyyqNbU8PU2UiOKG/YXw6XEM/EV0fd0KEGANJ4AAzXCfy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c419c3e1-529c-4891-baa8-5305977ae164', 'TFF335', 'TFF335', null, '$2a$06$IB/fQhT9G7QvuKg80I89AuFTDaMFp6CMWpw0wn/TZaV69kwkBbL5K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c439faec-8075-4f26-834b-0e562614ce4a', 'MTM454', 'MTM454', null, '$2a$06$iCRA1gvaoy5qolXZxGXbKeDQd/uFiD7tDTjW1lDwma57FsMNMcNWi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c45db678-8e8f-4037-b790-b2d7e4e56c93', 'TFF260', 'TFF260', null, '$2a$06$IVYv65CjasNiHG1BvwUQM.WTCoPKDVSlRz4Np.KcXx0h/lHimYP0G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4629888-94b3-4364-b264-b0fe6b433e5e', 'T067', 'T067', null, '$2a$06$6TD0Ec2BGZ8veCSPmcmAROMVNSzDBaKdCwMzqTrMIwoEksL1FV3rC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4987e1a-6374-4382-b576-b55d06923089', 'TFF063', 'TFF063', null, '$2a$06$I8GSY2TRpw.Oz5V55mE/juViaAqGKWS8yCO6Kss7F2WeWCmoH59Ai', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4bc6ec9-0ff0-453b-924f-5c7bbd4144bc', 'TAP007', 'TAP007', null, '$2a$06$N4i7QWnYqGRDTDuDEnRi1uClMUkbefWqrzGogDUBzyFOhCpytPFna', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4c2817f-1913-4a9c-b579-0a366283f44d', 'SP111', 'SP111', null, '$2a$06$5qF062JFgbyVBUQWC6toHeXN3wUNqae35rqjZDXUA0zxXXRDH6cPK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4c9edce-f10b-4766-a4d8-6c005a00d9fa', 'TAP039', 'TAP039', null, '$2a$06$C0AoBJERMyWc.TdLgrMOvOvICLKzgQf7LqSH4IqfhsAasGBPrgLae', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c4df226a-6052-4a6d-b095-92a8f62b5675', 'TFF145', 'TFF145', null, '$2a$06$9gHENdrMG0BiBDVozqX33esYwjGtKw.xX/i6jYM1cTs4C/bCvBegO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c52523cb-f099-4a8d-a5dd-3aa2c2bef8b4', 'SP072', 'SP072', null, '$2a$06$9u7kTbhJdQtEqYs/uJ/yIe03FKjAGuuF4xvxh5J8kTCqkkuak5.du', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c5290b65-9826-4a9f-8338-3effdf9d0000', 'TFF396', 'TFF396', null, '$2a$06$0gNe1tfLuMDN5OhfdB1AMOFEmK3jt0Q0gYXvG8rmO3QNQiqkvvDym', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c54d2e68-c488-4d2b-836c-d12fed58e134', 'TFF135', 'TFF135', null, '$2a$06$KNSEFcEBmSgJaAtRUDp77uXRMUtgKhYEAwFySXSKV5IMkSZYbq4Wa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c559146d-e108-446d-8abe-5b7132cae26b', 'TAP112', 'TAP112', null, '$2a$06$h7JToy4NdoFWFligrXXvz.YYoiijRhC9p1DaiBob8Ml0PAFjgsv3m', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c58ae3c4-c5d2-407a-b7ac-17e506018d74', 'SP421', 'SP421', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('c59d6a45-962a-48cd-a48a-e9f65acb4b2b', 'TFF161', 'TFF161', null, '$2a$06$8RlVqWHvXpoQmfJNiHf.ROydufzA.gbJsFj8Mxw.gURVblSPoPXUu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c59ea4fa-2f6c-47d5-9f64-99e0f3a6a139', 'SP310', 'SP310', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('c5f2df93-617b-4e43-b141-ae2764c3e820', 'TAP265', 'TAP265', null, '$2a$06$3vnyRNHZARf/ljWv13mO5uvw3GC25UIdA4HZy5nlUcnXVsSjMEcPW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c5fe8f9d-fd99-4cf4-bdaf-9a26919008a2', 'TFF486', 'TFF486', null, '$2a$06$wMWaM/762F2i805jOV8oqOWa3f/7HkLk61R2dJtSgh2M442UnxrWC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c605b2e6-78e6-4747-bade-4185e310d96f', 'TFF367', 'TFF367', null, '$2a$06$UwkVvyuvMx26o8VTekUg4OAE5lYxtpJdpNG8WqiXAduGGFk1l7Q3.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c66cc16b-8775-4e22-98e5-5f7c33f5961f', 'TFF422', 'TFF422', null, '$2a$06$C5/cj7QfqVuapYqIiR/LS.rT6QTZZa1efKmx095BA2AVmgzQn2eTe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c68faa58-0bc1-4025-b0be-63fad1cbcee3', 'SP394', 'SP394', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('c6d91ecd-4a2b-4775-8993-47074756d8f7', 'TN03', 'TN03', null, '$2a$06$JciHTNtyE33zFXnEzlgwdOsGyQMAYmeV48zEH9FwyfiS.O3xAsbB.', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c6ebfb24-3e71-49b3-b84e-2f485c9c05b4', 'SP097', 'SP097', 'https://search.google.com/local/writereview?placeid=ChIJnzmC01E_aTkRwXH3wbCVk14', '$2a$06$Ld5vxUsbCovKIoL3eshwP.QDo23MjF5YkxtpmUF96fy.w/mqrhUAC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-13 06:02:43.944334+00'),
  ('c724147b-4bd2-4506-be55-0fce82441422', 'TFF303', 'TFF303', null, '$2a$06$hmklvFEzfFQ.nngiL89qPeimFncdh/HviC.dGPzfh4rLwSMjk0dIy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('c725a1a4-c815-4357-81cb-bb4cf4495782', 'TFF249', 'TFF249', null, '$2a$06$lYb88N5Gm1ULa0nHIy9i4.EXBOPhok5x2uO2L7qVktudTLQux16gu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c7322353-afd3-4254-a5d2-1d42352bc8e5', 'TFF391', 'TFF391', null, '$2a$06$IvVRd6NLxCIyQ3G4iw/z6uw5N/KhVqcCPbBEwjhs6XqFCnnh5WQTW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c78c0b0b-db3e-49f7-b43a-740e1d50fd90', 'MTM277', 'MTM277', null, '$2a$06$W8l8cpDduPCKRwF89wUn6.uNdAfxDIJtUW/n1Ql50QVnndVfGzXae', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c791fc02-73b7-4ddd-9116-aee6f7eab286', 'T181', 'T181', null, '$2a$06$uB64Gw7FxO751eD8EdWtaOHN9grV1omTDk5EXlBmGxhta0nf2295G', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c7a6f6e9-71d9-4015-91a6-82efbb7929cb', 'TFF010', 'TFF010', null, '$2a$06$gTMWiMLqtO9st.kiKxJEF.5/9.aZ58iErQqL4BMk8xk6WdhBIYSzO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c7b1a7e6-094c-40b7-ad3d-cb9725bf2805', 'TFF317', 'TFF317', null, '$2a$06$D1l.lJNA.rDY0q1VR7uyquUsWFdrYDmRFoFq16KDnXR7MUPBlUGlW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c7ba7759-603b-4e31-b56a-c728efdb42cc', 'SP251', 'SP251', null, '$2a$06$ui4lJH3rOCgQisTi4M67regtQnP7t3TyV6.s.2H2iUGwRKHAeJ1ce', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c7de1a5b-1ef6-4ad9-bc00-01822c0ee706', 'TFF320', 'TFF320', null, '$2a$06$DpCwZL8rgo0nUlMa6fuzs.Nbaf6jU9haJl.3V0aDJ1ll43Z2LV4C6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c8046359-8c96-41cc-8a59-0588b3f10034', 'TFF049', 'TFF049', null, '$2a$06$OWJwXD0kbb0ZPKm6ei6gtetBhz/qoOM2lDGn20vM0xO3E4z1RacFm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c80cbcd7-b488-402f-90be-ba24ab2080e9', 'TFF346', 'TFF346', null, '$2a$06$/1BBixPZIg/jiOIuGYnuEuAHwYUv.O2/cyWBEGuUWR5b9GVKxM4tq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c81143dc-5e77-422d-b80d-64690bc35236', 'MTM366', 'MTM366', null, '$2a$06$6pNfksp2pT.QTm0vevTZKO3Vo1JPD4TEK5HLm.s3W812c0OfhbP/G', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c83b9735-5fef-4908-98c5-4c785c03ba50', 'SP393', 'SP393', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('c8435aaf-5ac8-46b5-b13c-d876d3aa1b15', 'TFF118', 'TFF118', null, '$2a$06$O8sSv5EFKAyCbnOfxL9B6u3tOeFSdkDAWiR6cX2G3hYQ1b/8NvXse', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c8465541-bc12-4a6c-9cc0-7accc8fe0818', 'MTM203', 'MTM203', null, '$2a$06$lhjrWBB.W/qWU.UeCzafFOnqrlGQOStzDhuZ/dAjoVIr02Ss8KDdO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c848c3c9-7705-420a-b1ab-4c3f543114f2', 'SP159', 'SP159', null, '$2a$06$aOaZzeGj0GlFiS2tOc73nuED4K3UbjJ37jz8tUr6Rk9454wf3B9Ly', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c858d959-d243-49f5-8802-f9749bca0886', 'SP354', 'SP354', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('c88bbbe1-dd31-4458-81f6-23e047bbb74a', 'MTM162', 'MTM162', null, '$2a$06$tYOnbQ3Jp5dkXxaNIVH5rui8jIx/PYRUk5hRlMTru8xnzwfDcbr/O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c88d114a-c254-4155-86f6-e023d0f94dae', 'SP183', 'SP183', null, '$2a$06$cEEpKrGQeblNqAH7koda1eFNeC9kyAUoRwUOIf5z.6.VN7EYZ23aW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c91e6392-c7db-4cc2-b911-f1ef58c00e9d', 'MTM379', 'MTM379', null, '$2a$06$XaxwsLAIRPUWll79mIZawOc6E4ZVYssyMJnH1B0ylw.tuf55ccUlC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c93d70bb-d614-4f64-8683-803d163a6d58', 'TFF446', 'TFF446', null, '$2a$06$tsR5KNOJ/Mlwb1bxHu1SP.pA.k.vpIuSOdGFo4MFqM9Ep36Witi/e', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c94189ee-bf01-423f-8220-957d4111e688', 'SP206', 'SP206', null, '$2a$06$z/WCH4HY09dN4Q5tYhbU7eu3uUb/QnZnc.9mqg2oFRNk11ojTy9ya', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c95994b4-74b6-4b5c-bb9a-22d761f83655', 'TAP132', 'TAP132', 'https://search.google.com/local/writereview?placeid=ChIJf25TjgfBwjsRltOx6_TA7mc', '$2a$06$4iMVcW0zZKSuj9MCKzPakODd.jZ0vIOnUbCY5N6YyvVdRuv8DKRoS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 13:11:01.061014+00'),
  ('c95fb78b-6cbd-4163-a346-c45e4baa32ad', 'T157', 'T157', null, '$2a$06$32z6R8LWZziBfVTHeiFdU.FFUc9Ym9zw6a098f8vLM2YLs5eFiK5O', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c9e87ee5-724a-4669-a43c-ce304c556984', 'SP179', 'SP179', null, '$2a$06$ixaPR2R7x3kNegzxTjy37uoDFjZ033S99QywcTlVY5iiWe2VSrN32', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('c9fa6cc6-e9e8-48bc-a257-498b9c7e4a1e', 'T127', 'T127', null, '$2a$06$PiLhUlDYtqPg4jeJqF3ZHOG3fWZthR/bb9ETNSi0yL1TlN7kRp/FK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca10e127-f4a0-44f4-bde1-97552fe88bff', 'MTM183', 'MTM183', null, '$2a$06$KVX/N6sxgLbYp7/0OVDV5.pkYsb5D0KcVWTgC/nBvG4ea1mVCY2Lm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca1911a0-f808-4b98-9f74-acc0f5557872', 'MTM171', 'MTM171', null, '$2a$06$edjovb.7lnEUEXbJNmcGQu/mZAeHWX6fRdQi7e9oFI6/T.GzVuMA.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca424681-0044-443c-be09-f110dc6778c5', 'SP104', 'SP104', null, '$2a$06$TTK3yiCI7RRGgdbX8.CgLOpnVqNzqjAoQOdwdBpgs4h0yYzwZodI6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca4d09a3-34d1-40cd-9c8a-42c76ab51912', 'T211', 'T211', null, '$2a$06$HOs7JcDKDmSTkWd5pJMBieloLudbhvCiLvRGfARHi0qQcbdAJ/2au', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca6d62c1-67c7-44ff-9e6d-3499d0b1ba21', 'TFF172', 'TFF172', null, '$2a$06$5K5fVpRunmvgtr5J2g31MeoI/4tlzMBPCychV2w5suqq3O1PbJq/G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ca785ca0-d721-4ff7-8d3e-32588eb71ac3', 'TFF442', 'TFF442', null, '$2a$06$uXf4yRet64JAASZJ5AAeiODg.dD4I8wmjTkyrdnskwiVtTUtI3Q0i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cab7ac32-a2fe-4cfe-8177-0a7df8bf8163', 'TAP054', 'TAP054', null, '$2a$06$qVaA.fVEI6alhaN6hRGXmOy.f/uyCedyDPdgosYpvp7wevKItKU36', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cade5579-545f-4216-95fb-ccb4152648d7', 'T224', 'T224', null, '$2a$06$h5tuEvZBd.T3a55ienHIaeVKkSaNN7t0KjO19pDn/o2csnj6u6PE6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cb591ed8-e833-4e0e-98c0-88e087960771', 'T033', 'T033', null, '$2a$06$oYdqpTVdNZxGvjUnVbknC.GjK6KuXPXPAY9ZkCGYXd0mUC8NAz/Kq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cb689a32-fed8-48f5-89c3-64963cb7c930', 'MTM434', 'MTM434', null, '$2a$06$6gUx8oqlvxAt9JX9XVnbHO9TNsuKhtYWNgPoFwyLeSIHMK97T5Dha', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cbd9294c-bcd1-4b09-84dd-51b37fcb9afa', 'T219', 'T219', null, '$2a$06$IomSnsa3urMHb06Lc4vIHe1cODSfJAPpaQT7QA8ilaSAIPxuZSbre', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cc3ac533-eb49-40c0-9248-0190e6752e8e', 'SP218', 'SP218', null, '$2a$06$AnUzbws.sirgGrjic9ixRu3rsxpK2x5YkKwKVydc5YDI051Bm6YXi', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cc45356b-a32e-47eb-acb8-9b4d379e0657', 'T081', 'T081', null, '$2a$06$9XoS.ijGQpOKaT1TS4XI6.F2egZYlGMH4TpF7yX36afUeWndXDlOm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cc78b583-75be-416a-a1dd-f81c7ec08cf3', 'SP217', 'SP217', null, '$2a$06$/ySlkZDqj0L9HqpoE1JloeqduAqLIxiGEopzvFy1y/NcqEwxOugES', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cc8427a5-58fb-4a4d-b704-f81083b38335', 'SP407', 'SP407', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('cc977d83-b5ce-4b76-92bc-3652e088f02c', 'T296', 'T296', null, '$2a$06$1kLkiVqzbdwQWOSFnqyfo.8tYAK0RSfMMqt6YXBgk6US5IeB/MCY6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cca790a2-85cc-4545-b908-4c94e6823252', 'SP133', 'SP133', null, '$2a$06$JA/Z.jqYv.B/XWj4ZGnDzeIrvBVbbPwkU0U1X4ZU9fho26I2nzOwa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccabc7be-712b-409c-9aee-76a38d40fc9d', 'TAP203', 'TAP203', null, '$2a$06$ZOd8OaPVQFOuBmFGy2FHkOJbHLBwkdcF8CKKOOTkMqub5REm3i8Am', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccae3074-ffd7-49ed-836c-6de5345c4b6d', 'T194', 'T194', null, '$2a$06$hq/1gUAPei.NjojxcyH.f.Z32D.Tk9vSVJgyZ.09yBn7Wv9PxO9Ce', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccd8586c-7b02-4de7-98c9-183b5d1763b9', 'T148', 'T148', null, '$2a$06$iiP91XQvmzJbVoI8zsUPGOvGDR4Vw3dqtvMqv4ZENwSjpdRdiIdeW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cceeec3e-a185-4386-91e7-68d359795394', 'SP283', 'SP283', null, '$2a$06$a3bORGCRu0u/ZbKiVzPqEe.coC5NwCF1V3/MKzWYzu.HAkrM1w47m', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccf3b779-c3d5-46ff-afd4-c089481a0a97', 'TN09', 'TN09', null, '$2a$06$Kj/52ShEJw5m8emNVmUhYuBxnRj76jwse4L.s4v.rWRfv9cegp7De', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccfa32a1-1921-41f9-8942-ce699f55c205', 'TFF480', 'TFF480', null, '$2a$06$kxoTtW57JAD7KmkdiktyXuH9lnfdy0uJhZoy28KuybTvnydX7CgEO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ccfa5f59-fdb6-4201-96ce-cbbf24870b06', 'TAP161', 'TAP161', 'https://search.google.com/local/writereview?placeid=ChIJlb8653TrDzkRLAXZCqPXqw4', '$2a$06$fwlM534qYHbbuYaN5WXOku1kzxGtpfwErVi3/mPY5xP2kuLzElMc2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:14:04.809439+00'),
  ('cd62deab-b9aa-48db-8ad6-c5cf5088e2b6', 'T133', 'T133', null, '$2a$06$fdrJzOHKgLrnRUu32Zh5qe30OWYITF8ERysZOf1jU1Ik3ftrlBX8q', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cd99409b-56ab-48e6-976a-2911d613e100', 'SP467', 'SP467', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('cdc3bfdd-7de0-44a9-8a4b-0bcf7a7764e9', 'SP188', 'SP188', null, '$2a$06$FtmwiaOpNgIi30BQWiTL/OjeZKfawdT7XHBdPT8uiHZWiWaxuC8vS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cdd6999f-e679-42c8-acf3-f4eb29110b62', 'TFF388', 'TFF388', null, '$2a$06$qN5pgELGyntIH88OjvcKWux.0dFzOrQ0uOLY59IZHuy4cjUObRYqS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cdff1d4c-a23d-457d-9d89-a168050121d8', 'SP078', 'SP078', null, '$2a$06$DXzotOXlRZaJvw8rEJvdOeTDqq5ag0Ul0zr5GHyqx6GI59wu0FsFa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ce0c7599-71db-4239-bea7-1abf703dddfa', 'TFF169', 'TFF169', null, '$2a$06$BKMSFYl.LE0Ao4agxVegButb4p2OiM9bwn4QRSkbbQl1ANz1BCa6K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ce5635fc-8531-40de-ba0a-5ddd993b6efd', 'T233', 'T233', null, '$2a$06$/RLQbOoSTHlbUU4dDS1Nou69PyrkzGZHHhxmki4zaP8mpqdTyqtsu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ce99c86c-98ae-4ce5-b3c1-c175b2c0b2d5', 'TN23', 'TN23', null, '$2a$06$JOQ/7Xs4Otd5QdOV0BE7EuwCy/X.66HclV4SRtgxHUsnk0vznT7Ji', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ce9ecb1d-da6f-4e5b-a558-e1152693c12f', 'TAP346', 'TAP346', null, '$2a$06$L7H/gUBjL3ALJbjS5Sqb6OJ7cL9sD4Zx5ben62uYZ5sALH8ujSsCC', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ceb25f61-b07f-4a32-becf-6facb4de853a', 'MTM236', 'MTM236', null, '$2a$06$h/SRjmIms8.9BQqNkBVnOu65M8Km5DXkFBlTGQ48cNJRMLq3YXNo.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cebf93de-0eb2-4363-b034-2af95d10e9d0', 'T066', 'T066', null, '$2a$06$j6ezfSqBR8Xz42T0nL49vuvGEsr/PSXQ68ty6TgWAs7LAV.2B9KJm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cee1b221-59cc-4dd0-a12c-bd906c63fa04', 'SP350', 'SP350', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('cee233ba-aee8-4864-a071-a0d9f564ce28', 'TAP217', 'TAP217', 'https://search.google.com/local/writereview?placeid=ChIJYQz87CrrDzkRXSkzTpaiXhw', '$2a$06$3DaROcBznQvsG3yolhGA/.iUDZS8zJaUAv52WxGGFObjmRHt0uSx.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:51:24.641704+00'),
  ('cf2ff503-6a32-4c42-857f-1f9b26435357', 'TFF294', 'TFF294', null, '$2a$06$2KGWmd9d2v7/iftlDJsvSuRftDwa/NaCWaJ58MQ9c21U7Vv9limLC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cf4aec7f-daac-4e47-8e7c-81c9835921e2', 'MTM242', 'MTM242', null, '$2a$06$DRvnHoQVeCHlcQ9.ZSFm2O.R0tR.PbNzI97THOs3sbhG4sagaTpdi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cf7ebe14-970d-416f-bf4c-adeb9b42721c', 'TFF203', 'TFF203', null, '$2a$06$Jp1QhhxanonsVLhDHI0RLus30W4yml0hwt6xuMDjTeK6vWPR3SFLi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('cf8caadc-bd3d-487b-a165-19e081f260b2', 'SP073', 'SP073', null, '$2a$06$NIlLTbBCRHlTZzXt9.OJse9qoCe1kFRNHtpWvn02GvPlZ3pKn.B/a', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d036f151-57f2-4248-ba5b-0ea76e67228f', 'SP246', 'SP246', null, '$2a$06$WLvaNctg7I0CRax0moc6AOyGIdN2Pv9ot3dkwXNJhcZk8Lcu7f8fa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d0396e82-c6c3-4fa9-a6eb-2ef515ae5aa4', 'TFF395', 'TFF395', null, '$2a$06$grfzDmsLU8.LaFc7a4lEOeC/CJDA97kxOl0KAM/xCYYbeeozBEGx2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d03b0e5c-fec3-43c7-8b5b-29de8e6e318c', 'TFF314', 'TFF314', null, '$2a$06$DGmqZrrp9MuUxDMvFuiLA.UacvJZdGS8kfo8PeuVOwlwR0iFYyDIy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d066c531-1147-47f9-b4f4-17218ed76cea', 'TAP119', 'TAP119', null, '$2a$06$F1HyBtsNN6FIRHjDR8b3IeGv6O81nyfAwnfAcjywOH4UMMk1sIwHG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d0772198-6705-453c-8e09-be794a5db764', 'SP377', 'SP377', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d0c4a1ff-4825-4fe9-9de7-4623ae5fc6e2', 'MTM449', 'MTM449', null, '$2a$06$w.imKb1dq89f9.1jvqsqHumiRW5ohJTAmhHnb9SwGPKvKBO63ygJe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d0d5f5a3-31ed-4c9c-989b-6382b11ba958', 'TFF418', 'TFF418', null, '$2a$06$9hgkL4U3usjqBInz0ucqB.BXt/sTMF600Jzyu0GerkDq95ILK9foS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d0dcdfc0-8ce5-4d85-bbd5-94ad766657d4', 'TAP126', 'TAP126', null, '$2a$06$Qvra7rEJHAgG/awho4fgDOpFVpyHaruG7k3OggwQfXQ/K.nMr879O', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d0fc71a5-239c-40ba-be24-364b12091016', 'MTM406', 'MTM406', null, '$2a$06$5xmkMS4vKSD5A85XyjP8k.2CVA80t/zbyRK0xOI9KzTbiC2tDHvTS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d131a3cc-fb17-4e9b-aa7f-1643cd4e86ff', 'SP139', 'SP139', null, '$2a$06$//iYrxp6Ct0ikhLew/SbuuLEFCGXJZ78xdhWoMW.rn6QPlftY7w9O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d15242b2-a4bd-4e25-b92e-a73b623731a7', 'TFF461', 'TFF461', null, '$2a$06$HQW/5cW4YoIUbr5A8RicvOe2AzAghsdX.K6QCAI9l3ndy9JLn6IO2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d17c8f62-0b43-4a1c-8ade-31f68d6cee41', 'SP067', 'SP067', null, '$2a$06$oLSqWyma/rruzFRwAMMma.msEXsaQw3bccUzgT2fic.nMQBZuIuae', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d1b9adb3-77c2-44e5-ba38-9e580db7e7a5', 'SP358', 'SP358', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d1bcdea6-b814-4543-b4dc-1ed60432526c', 'T240', 'T240', null, '$2a$06$0eSb541qFSX2Vapq6bPEWu5WyqZF3PD3s4.zMRgmkg91Rg0EcGnU.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d1bf44ea-0c81-424a-a61c-1a3d40541a1b', 'TFF131', 'TFF131', null, '$2a$06$sXL.IwA4tY71sfG19GfipuZhCSt/A.kN7ekUn8BHYaLQ5AT0NqZI6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d1d82521-0473-41fe-94f7-38d62e2205fe', 'MTM176', 'MTM176', null, '$2a$06$XlPpgm8M0UmvJvN5eKqJeOQDZjsG5xdpDxlU5HqUsEH42nee3tifu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d1dad6f0-58fc-4f9e-b91b-2b5bb183ebcc', 'TFF244', 'TFF244', null, '$2a$06$4LQ/nCY7bf7t0UVrD8FvCuo5rtOKOhlu2E/0NHdgS1MvySFjUD4Pi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d1ea9b37-d309-4ca2-8fc5-b509af126240', 'TFF150', 'TFF150', null, '$2a$06$hXSAfMDWy/LIUHWOouwOqut752nSLok8JpyyyTMRuFnl3T5bpADDa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2140d08-948c-4b13-a94e-ce01507f01a5', 'TFF253', 'TFF253', null, '$2a$06$V8K/d1R.0N/JY3mc7SO9hO5AYFpBrvw0rNJzJ0vdUVBocZ.VxZB7.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d21a06b9-1361-47e9-a530-06b274275140', 'TFF255', 'TFF255', null, '$2a$06$Spa1K63HeWi6RWC6Dd6KQu3xm/I1NuqcLkzgxk4TYVTJSJrTv5Peq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d221c4fe-4205-4151-8171-503882cd2ed9', 'TAP307', 'TAP307', null, '$2a$06$hMlHalT5qiODH2hEfKAL2eh8zPWRN.VhReanHL.NyYm6Ss6EDrQR2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2484535-4459-49c8-a652-ad250079d7d0', 'T173', 'T173', null, '$2a$06$h2M7rQkXaCmyyRiRDSMIYOu0eo5VrxVp382ym9hnOq./yZJXEN3X2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2ad6264-633e-4ff3-9ba5-4fcbd59d3254', 'SP349', 'SP349', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d2b56466-e842-423a-b7b7-07233446dd12', 'TAP118', 'TAP118', null, '$2a$06$TIEcy7IfSClTplSZ8T50kuVuiWqL8MX/IRUT9rxSCj2jxkQUSoi2.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2d2b3dd-6191-4c68-b270-571bc58ad349', 'MTM340', 'MTM340', null, '$2a$06$JUOj7ffOPycJR0U3OuEfUO.KBnip7XxlmMevlqaopwHGffqrjW6km', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2e269e9-d96f-47ef-810a-2727e3cb6f58', 'SP391', 'SP391', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d2e675f1-06bc-4d8d-bc66-9d70dd72ecd1', 'TAP312', 'TAP312', null, '$2a$06$IQ512niYQuz7MlYhQfvbBe.LKPG8KOK/dAU0QjmYjVMTk3jaiSIO6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d2f73fe5-5ae6-407e-80f3-f90e04cd5ac0', 'SP355', 'SP355', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d3478250-2889-48cb-aada-8265a3c44486', 'SP277', 'SP277', null, '$2a$06$vlq.mGtvfWT0khKh7XSUaONdAVYH4xNMEDi6dpyjmOUXr2KNRote2', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d360238e-e8a7-447e-b987-94cae3d5590d', 'MTM229', 'MTM229', null, '$2a$06$r3UHEugkU9QQczXw/8oa9.SyJTDr5Ob6aSFxJF0N1Ms49BGl4q/Q6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d39af512-49e6-4252-b7fb-31f3c6c04bbf', 'SP087', 'SP087', null, '$2a$06$UGAKOhIXgoD5LBjkci7gPefq6MESPcy9PKuG8aN164.zlgH32/fqK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d39ef073-71e0-405a-923c-bb19e18af228', 'SP082', 'SP082', null, '$2a$06$Cw03geK/klsuAU3rv0CoVes69r.XvCm1bq7Jyxl7.otBlYV8RkDOu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d3abdcc2-9551-4ba9-a559-0d22cef9ff41', 'SP269', 'SP269', null, '$2a$06$PWOIidWmbeFcdFp7Nw0Cuetm4Uizzl5j0pLtV2ZXbwSXGPWMwPVLW', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d3fda0b1-e693-4b84-ae70-748d27b22da4', 'MTM384', 'MTM384', null, '$2a$06$P8DEB8hX7cG8S3.WjkI17e7xj/SmMibOAJo1ydZt0tad.QjSeWCvq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d3fdc289-7a97-418a-a4c7-9816d02bd4f3', 'TF08', 'TF08', null, '$2a$06$D3qId5K0C43bNbAQeLo17OqzaMl3cscmER26fWszF27Zloe35I5gq', 'active', '192b512b-f822-44bb-8943-824dcc0b12f2', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d409f291-c3e3-427d-92be-620f8a548834', 'T119', 'T119', null, '$2a$06$8hVM0jwz7zDmqA0uWRYj6u8Wn7xxiI4IVs.3iqPvmFE5T7STmnLU2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d41242cf-ff62-4775-bbdc-3f5e24d91f9e', 'MTM130', 'MTM130', null, '$2a$06$iudr163m6yb3ZORy.s1Ue.UFNDYo1mpeX/7n.8jLeipg7rNmjUx7q', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d453dfdd-ad70-490b-b8dc-34dc62c9edb9', 'TFF493', 'TFF493', null, '$2a$06$dl7ws8/bcUR5D6WpBSwgfOpm25ER3n6ReF2fmo36rHpmJDuH91Nsq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d45a0eef-1c4a-4ec9-9e0a-53b4162ec250', 'TAP129', 'TAP129', null, '$2a$06$GD9KWMylayPtEbUUiU7XgeBK3aIU74bTxfMmaOhDa2jo5RbTAS8bm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d4814164-0711-4bca-b86c-cb8ebac86a85', 'SP418', 'SP418', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d492cac0-f288-45a0-9863-35be8f2d356b', 'SP090', 'SP090', null, '$2a$06$BRi17aVOnsJophVhuXxWDO.9P5YMISKh.D4gv.SWw/YPQrQ7fprrG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d4c288fe-4055-42da-80cf-66fdfbcf9726', 'T030', 'T030', null, '$2a$06$WbkkiQ0kdV5j9aafNiVPteVUJoLjRjjr2v3xks.zknjW9yxxixsSO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d4d20f32-643d-4699-8dc2-b9cd2cca6b49', 'T191', 'T191', null, '$2a$06$Sze/.91r6y3jgDGwkOwJuusifdHNdE1L5.56Gq3dyiNVWt0AjfULC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d4d23ffa-6aaa-4c98-a88e-5b203c9572d0', 'TFF153', 'TFF153', null, '$2a$06$t4FTZ8uc.TJnUMUoCwAhQ.4WNDJ8z8DjfhDV79CjAh.x9S2KOdF3a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d4e587c3-96ef-4921-8679-e2192c1ea8b5', 'TAP281', 'TAP281', null, '$2a$06$DpCHm9KZrzPthk7M5hSgduLUWbnpMORTg.RqSojmSyDJwJ7tl1Vji', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d509cee3-7c47-4215-aa7e-efa96eea3af2', 'TFF191', 'TFF191', null, '$2a$06$GlmCrxRVZk2GqsBgH05Qju7qMljGWBUnbczyolhusXXCuLIkYFK6i', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d59edf2f-f624-46d1-a23d-115407e18592', 'TAP025', 'TAP025', null, '$2a$06$RK0NnBReBuUIHXvRn0kry.ZtvXAjieZlOfzHd7/bEaAR6iLwZKW8i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d5b520a6-5de3-45f9-8809-538e9dff3578', 'T246', 'T246', null, '$2a$06$c3VYKkGOHcMIgkvQzmcPCOAN4/f84.ZSaUA2POgL/HlhJ6o.tluZe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d5c8c35b-f494-4c96-9980-979eebe968a1', 'TFF159', 'TFF159', null, '$2a$06$DFlKNt9vGtCpImrfoIjxfusYCqU0iZudFC.8hGCpKZbd8DAuyUUhC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d5f25be2-e910-48b7-a9d0-3453abdb91c3', 'T197', 'T197', null, '$2a$06$6zHWn7yhBYu6PHiW2FPAteCLq/oZWXRwAPHQmMpGi8sfzt0BGAR5W', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d5f33af8-77a5-49fa-89a0-811e4b420e48', 'TFF001', 'TFF001', null, '$2a$06$.3qoSw39CDu0hAkTEP2ci.JCgefJmfCi/z5x.kWTGAm5L9nKL1M.K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-13 15:58:03.32849+00'),
  ('d61aa4ce-62ef-47d6-a6a7-940a839a75b5', 'T062', 'T062', null, '$2a$06$XjlQAKLpXCtpsYJXqNXAle3C2.yGuXaK9YxCSG3TaKkrjXCjX5Mk6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d62fdeb6-85f9-450e-9559-422b2ded928a', 'SP163', 'SP163', null, '$2a$06$9U26oPTdPY1/mlqXvQ6CvuJ3bflOFaAeCeNE913p51j8pAJCBj5Mu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d654659d-da50-45c6-be1c-883c491af64a', 'SP436', 'SP436', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d660bee7-5121-48ca-a7d7-5fd933b3903d', 'TFF373', 'TFF373', null, '$2a$06$pMCpDzHeHfu..y1vcBU4Hu0rkRaAvrkLzx8M3p1/kWZelsjWbE4ei', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d667524d-6907-4121-b069-15aab3bb6283', 'TFF321', 'TFF321', null, '$2a$06$Zki6C1dVM6a6mEnMnCk/9eWmqHDsI2dC6LSkTCnFS4ekn3V8CSfHG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d69a6de3-2d4b-4d25-92a9-b755b3a03e47', 'SP112', 'SP112', null, '$2a$06$uD7DpFoljAOrO0YXpZj9RuqfghyzzXP9U6fzhCrKBJ3T2liuZLNEy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6a93d1e-56b4-4311-8d89-77f7daeffdbc', 'T170', 'T170', null, '$2a$06$Sc8T1WYt.xX/ohOc4LIjC.Yi8H4FCtCzhQYmOTa50YqIRTxYF/vxu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6aae5fa-89d2-4407-a3e3-fc359819b10a', 'MTM374', 'MTM374', null, '$2a$06$8bxIBWU0MXYAqFzmoFroh./fW4/Rm9OfvyjxYrIe3F0rCdjCoYJgu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6c0213e-9db2-42fe-83b4-a3fba9a6b015', 'SP215', 'SP215', null, '$2a$06$wl1tEkkdUO3Ph4uIXON1quxV9o5Y1v5T/Hw2q3wOfgP1SqnL9GC4y', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6ed932e-4bee-405b-bd3c-43aaa0b86605', 'MTM223', 'MTM223', null, '$2a$06$ajSAhlX97d3CU5OPTEBAIOCUyZfIRsgZWvNMXFqF75rh9TnzAfe2e', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6fa725a-6c3b-402b-9a8a-e13c675f222e', 'TFF325', 'TFF325', null, '$2a$06$P5mqeizLGogZ/xPDi.5CPOAIoM/bRrgrV3M3OfvzfE51ABgtoneVi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d6fbe7f1-d238-4eba-881d-b7c8bab80d8b', 'T214', 'T214', null, '$2a$06$HBBKdyLqQ/Y1.fxj4i290.EK8w69rvmoxQ2OvoplbJsC4obYto4U6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d720218b-75e7-47a0-aa77-51e3d53f06b9', 'SP373', 'SP373', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d722cfc8-ffc9-4c48-b19a-cd55806174e0', 'TAP197', 'TAP197', null, '$2a$06$3gL/I8RI1PrCoLLI7luZE.uAGUyQ5WJ5ZId8WH0cbL2ORcUkzVZqm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d761f4c8-749d-4fa0-afa7-b382b8086599', 'T156', 'T156', null, '$2a$06$4GAi0ahT5l2mWGLlYzMb1OL6bIXnwFhTWBi2XWWqTZ8TBm0yIY1I.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d76b422a-43fb-49f3-a0fc-abe80ef96525', 'TAP035', 'TAP035', null, '$2a$06$43oIjUYW.YnKG6c3dyVrmeozi4Jy1rk4Mv7muZ3xQuvOB0NVGo9hS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d76f114a-a6b9-4b2a-98c1-b96030076736', 'T108', 'T108', null, '$2a$06$WOf3cDMEH/ktpqZxY6xXKewlwlFKmCJ6wK0wFtCKfz/hm8pAe1aY2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d76f9644-a39b-4283-af5b-43d567951fc3', 'SP162', 'SP162', null, '$2a$06$p6Gy0YsTdfP9UvaUWjNWCOS3AE8Z96Y0QJ/0fWKUv/h7e7P3VQXOG', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d7744436-cc1d-405e-89b9-c0b4b3341498', 'MTM205', 'MTM205', null, '$2a$06$ybwAG7b7JkaFKZ/fog7PxuYy9wjhbIQycTC8115jHqz8HyV033BEO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d788a859-f2e6-4364-b4a7-f56190758aff', 'TAP306', 'TAP306', null, '$2a$06$7rSwYRwK/p24HR.dLGJJBeIM0q7GsPJXVKJ5KrYHu9oAgBfX5ndJe', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d79f69a6-ecb3-4763-be57-0963b2bbec8a', 'SP010', 'SP010', null, '$2a$06$tppcnqNAqrfv1WE/5ljPref0gJLHZS.sEHQXfoEVJyM6QPT3kvYVO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d7a36b27-85b4-44d0-88cd-e53a0de4ed75', 'T165', 'T165', null, '$2a$06$3QSqZnQkCc1ZTzxv93Ajauf0flktDlJmqIzYiTnZsl3w.BTKsMCwe', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d7d01118-778d-4e9b-a7be-6fcd75a97b54', 'SP347', 'SP347', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d7d5d968-d30c-4034-ac01-5ad8c97beb04', 'SP193', 'SP193', null, '$2a$06$7uEUvnXlILvCqbrXPspLruPgS4iX4G3H315NV/bB9XoSwdirFFGEK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d7f4bc3b-8cc7-4514-9160-df0a020f5cca', 'TAP020', 'TAP020', null, '$2a$06$bQMnAnfv0joRuO/izX6TdOmRshqbL0vnizpBlMml8eCouYf9bmCOW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d7f93c6d-b2eb-483f-adc8-4384d9beaf91', 'SP222', 'SP222', null, '$2a$06$2pjw8dwPnt2e7r0voux0ceYb/SzShHDaMIRg15AAV4CaXGdHM1rCK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d82754f2-1191-4485-9c2b-cf53b098b409', 'TN10', 'TN10', null, '$2a$06$lZsu.H.zrLTp3jTfrNyykOkAghQ4BFAQG89bNTKVHLE2Ab6.d.Mdi', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d82789ad-8fd2-4515-8b4a-d19f58d6d707', 'TFF089', 'TFF089', null, '$2a$06$eVvMj59kd73MBqgXUCmIMuaYzOAftEyBvGVNLeHrA.Gty8jEyrS7S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d82a38c2-0d55-4da8-b36a-6e66396d60e3', 'TAP037', 'TAP037', null, '$2a$06$jrdtfabBY2rR7kCN6rNdsuN4AlOzvCwBZumMtMj9rFSa155/WU0Ii', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d8352c58-2447-483b-8183-6e3827b8690e', 'SP029', 'SP029', null, '$2a$06$HvJ8xd2cvD8MekChXF9ApObofpAghjDDnkAehaw3AAfbRkz2sG3ti', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d8ce504c-c875-47ce-8ae5-05793f0e8c39', 'TFF427', 'TFF427', null, '$2a$06$szp.4eEXYqyhHEdjRIgVNewcRZJ8/tnw3Ut55aDQE8nUEHyxI0aXa', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d8dfb8e5-42f8-44ed-9be4-2c1ac27c2026', 'MTM212', 'MTM212', null, '$2a$06$4iGOsTOqhi5r4xUX7mZbp.Ses4xXm/YlW69l7wIdhJAU3ckoKXMjO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d90de1b1-2f95-451c-99cf-21a0c80f915c', 'SP461', 'SP461', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('d92af531-e954-403e-9c90-308f93a6593e', 'TFF293', 'TFF293', null, '$2a$06$748pUDdPqmKof8ykieEYzeDTm.C7MiLtljPkJw7/DmpwihkeU0FeS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d9331842-92f2-42ec-8715-0f42ec62e820', 'SP125', 'SP125', null, '$2a$06$PmnZioz1HUEp7Jk0svka8u2EFotVtKo1ddLG4F09/ideV4nt4WGHq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d9434388-a1bf-4902-8f22-95cc9d0efeed', 'T158', 'T158', null, '$2a$06$ZgI2fCQOMHvowsWBoPLfcOcof29fQoKs/faFQzrLYsKhvHt6Yaw4i', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d98dedb3-40fb-4121-9838-fb708aece3e6', 'MTM272', 'MTM272', null, '$2a$06$cChmWOMiwSLdMZNYFpvom.gc2ceuwJqlTkn3UORY7SQPLnCB1sTC2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d98fc803-e189-4f99-98be-3c9cfd484150', 'TAP128', 'TAP128', null, '$2a$06$jt1QorKBqeb6fB/.YBGxBejAkW6PJy2fGW81.TzGSIP2j1pjsD8PG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d9adbf00-1d70-485c-adca-19d7f481fd91', 'TAP352', 'TAP352', null, '$2a$06$FUVGPIGF2T9l0iMwG01fBexspYugZW3sVRBg5Dj/UXnyEZwgUmcQy', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d9c53a37-42a6-449d-b54d-c46842cfcd93', 'SP083', 'SP083', null, '$2a$06$ZzzJ3aLlJz5cnPgGYzu68OTAnWrIZmHj5.s4HppwG0LaqwV8614Na', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('d9cfd1c4-a49f-4d05-a1dd-14be1ebc62d2', 'TFF194', 'TFF194', null, '$2a$06$L3bl6fiZnldD325wrM5lqeLUbHBNIiE8Sp4yu.iFfyV4JhhBi2Yxm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('da071795-4781-41d2-bbef-be69a60b67fb', 'SP301', 'SP301', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('da40be65-1faa-4910-bf25-063a1c97ef2b', 'MTM283', 'MTM283', null, '$2a$06$oCGGEDowTh7ABMYc.h0FQ.axGpH8g3B/r.OL3sWc6oGz3I9PAYcyO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('da42ca8a-a060-4488-9f57-d4ca5b4f6aa3', 'TAP088', 'TAP088', null, '$2a$06$ntJt5Gbr1cVcIDcIAUkzbejZnxmLAjpkafqFeuckO3g8ttILFxCCC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('da54f51e-cedf-4a66-96e4-ad8ed6a671d4', 'TFF040', 'TFF040', null, '$2a$06$BhwqKh805apavqcsVnqCiucuXLyINdlJh5IBFKeYdu17MzYd1TPee', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('da706069-5e5b-408e-974f-16f1c130e150', 'TAP121', 'TAP121', null, '$2a$06$hiUun/eMmVUP7oHRFhjcmuiStfpuQNf5Yb/GmKP5n6hyVKI10LQwu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('da9cc542-c2bd-49a4-9446-ec3cceeef222', 'TFF273', 'TFF273', null, '$2a$06$uTmsKwqVnivGCtg7s.dykubboQ0ar.ubZdPdLBq4nxtC35zAcWon6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dab56c2d-94ea-47a0-86c7-52258f0bf474', 'TAP159', 'TAP159', 'https://search.google.com/local/writereview?placeid=ChIJZwtXDADrDzkRHS8ZphRW28A', '$2a$06$vLRxVnHxYXrzbeADH4CM5uZCACHLcunKNskIB72KsI/XZsGG9ThY2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:17:44.710605+00'),
  ('dadf250b-c485-4c63-8126-69202400d09b', 'TFF380', 'TFF380', null, '$2a$06$MT2AM6NWdKqxmbFdxuawW.MgLYi5MLCdwoa6SmtQDdhG3vxpidjie', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db0c2888-871f-431d-a1b1-743027bda59d', 'MTM142', 'MTM142', null, '$2a$06$K/hUWtU9N4nd94LuyySAz.FJXVHmuEfe6pCILvmcjXYXnsdkD.UqK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db0d20a4-2955-47e8-b577-eaa4f25b9ee3', 'TAP147', 'TAP147', null, '$2a$06$kcbjrbZYqIr5eacNnCcsiOQzUriXfl3gp.K5Ax3dfTOfPE1QpIeiO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db2109a0-22b3-481d-a557-43d335e3768e', 'T109', 'T109', null, '$2a$06$p1fSjgdjXxyHJTzdUSy7Nu3m4YpUKUGlq4OO7HEo7lpw4Yo6nTvsi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db228063-e42e-4f0e-98ff-9c3db891b4cc', 'TFF357', 'TFF357', null, '$2a$06$vYmaOZ9mIJm8stxYFbgwuuARbawviV0bhfo6nexjvtXOvBC2wuqCi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db5962d3-73bb-4238-9062-be11234e85cd', 'SP339', 'SP339', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('db60f86f-cdb2-4f6b-94c2-0262a6e58df8', 'SP497', 'SP497', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('db670081-4d1f-4f96-a7a3-3b2f7394dd51', 'MTM310', 'MTM310', null, '$2a$06$EoWYQBCzRY3Wlt8meaFgR.wMLdSErduJ5ioZwK4guqks0uEiR26M2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db690176-590e-485b-89d1-1a543efb9fcd', 'TFF062', 'TFF062', null, '$2a$06$ZB1htkK87epgpNTo681U4OZfFUpEq9y/uEx6fXvaBnQKMMVesty1S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('db8126ff-1c60-4082-b711-8da559a5b66a', 'MTM209', 'MTM209', null, '$2a$06$T7HmpHE8hu7e89g8Id69z.WJKoz2YrpuCW.ThNLvDNJKuuiCz7D8a', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dbb37ee0-5a24-4cbb-90be-c25ff970b446', 'TFF064', 'TFF064', null, '$2a$06$e.nc1OsOoM7/s3YdIKLD6OowZvh5TLf7X0TBHDGbaj88K.yfkOVCO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dc00905d-4ae9-4b39-8344-8b845e972f8f', 'TFF075', 'TFF075', null, '$2a$06$Qg3TSXixDxNzjjYuHVhgNOfb3kriIUNvHVEpmeZQD9ykzpoul3SVC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dc1a935b-e810-4a18-8608-7d280c347f3d', 'MTM158', 'MTM158', null, '$2a$06$DD5rc3UPitkX/ryj125K9uBT6IyMkHY.LR1N/P7ocRGz7AcIWc.C.', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dc56d50d-5bc4-4476-bdc3-b0584f456639', 'TAP076', 'TAP076', null, '$2a$06$eBZMQFja7mcER9GehwbjRuezOHX8lcBTTRUnX70HQa4A57JitDY1e', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dc70d608-98c7-403d-bbea-d91659c0ad9b', 'MTM356', 'MTM356', null, '$2a$06$26srvd24nj500H4XrNXgnudsfk5/DCSaipqeyempopjuF.9p3wNfO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dc846899-c483-4f35-b0c0-0dc24bba65e7', 'SP498', 'SP498', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('dc9f90a7-e6e3-470e-8b87-bfd2fd86bb64', 'TAP042', 'TAP042', null, '$2a$06$k33Nxc4ZHiI0c2yuOgLJdeNa8b4k/KADX5I5ry23cbHdLgWcNHpyu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dcd3adf9-f47a-4d80-be12-a2968f5da58e', 'TAP198', 'TAP198', null, '$2a$06$gd/QvFD7TO7ddtozMJOYb.3Z3NquWjO/MEF2RNwtsP/5yeFJoUgLS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dd313818-dcbb-4ff6-af5d-9a677f8a4f04', 'MTM362', 'MTM362', null, '$2a$06$h0Nbixdi3lKRZTwEVnPvNOcFjYUzq0mctSVJbMTCGOC8dlgHG9Lgy', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dd3d5241-0d53-4b9f-a493-463850d54234', 'TFF014', 'TFF014', null, '$2a$06$4wYxujHARCcOHsMQa8qVY.X7E0JzPVte68JBV7.M7nhRUGSbNpm2G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dd72a0fe-196a-4343-b9d1-4da312d4f556', 'T099', 'T099', null, '$2a$06$JmtKxdfzQuDCI//Ev037NOw8BDj3S7oo8fBuZbHOEr1CZg2bTmlV6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dd9708df-6658-4e0b-8f2c-a51644072b1b', 'TAP383', 'TAP383', null, '$2a$06$Bp.g0ZddQlzrE.llnH6DI.aq0KYzPTiNWQ9T2rw/gToyOUKTDia/i', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-13 14:23:40.653828+00'),
  ('dda8851c-9664-4491-87cf-04a19547b9b5', 'TAP321', 'TAP321', null, '$2a$06$ZrVpd1AknKqfoRBjHj3H9ubVGtoGGbzilYwMmmsPIVMDBdKdT5AMi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ddbf83bb-dd88-48be-8c37-989502719a6d', 'SP484', 'SP484', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('dde7168c-51ac-4725-8e3e-c2121ee3d974', 'TFF424', 'TFF424', null, '$2a$06$BbQwAEsV62dMKqP6mXq3JeIcROPvcHS1A5ECBn/kmJKyRnYhEThmG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ddf72f35-da98-4593-9e06-5f69cc41ca9d', 'MTM251', 'MTM251', null, '$2a$06$84hIdBa4j1eupLRXwhZ9jerJ6KblLnrsDyN0lwxhj0chMIfFWdW3S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('de1a4de5-5b33-4373-b59c-5d15c76f04ad', 'TAP048', 'TAP048', 'https://maps.app.goo.gl/pudy7R1tXP3UxGXe6?g_st=ac', '$2a$06$S9eC6oAuGljxkNR.PGfk1eXTbKsAmGboTydipXTTAjfYZ1FXOwERC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:13:39.267181+00'),
  ('de277a5d-b206-414b-a70f-8753f0eecb06', 'TFF016', 'TFF016', null, '$2a$06$wpAipIfqWLp2z1QN2rOtgeH/Jg4YaTS.TZ1GeR0Ijj3PNqXSizlV.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('de375d98-923b-466c-be81-4d3d8018180d', 'T172', 'T172', null, '$2a$06$G192C8AoKOShMrned8URGuRFUgSv5Jiy/F0ipYTvfnX6SOYOchy6m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('de3d6f81-f431-4c8b-b705-ef90396a4ae0', 'MTM363', 'MTM363', null, '$2a$06$V8wKa/fFhncrB6BGmreaoOy6hR0oYCM6b11/DFqrAsX0dpAiD2URm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dea83cd7-bfe8-42eb-a72f-92a9782852ab', 'MTM407', 'MTM407', null, '$2a$06$q7rsggEhxxZ9XUWrk7O27enRLP071ELPBaZGow9uSFwR.ngAAWqkC', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dead24d7-6ba3-4c94-9114-bc5914342c10', 'MTM404', 'MTM404', null, '$2a$06$ZoYsWBk9XTmwlFwRaIu6neJuL657d/AkiNyl6x9gcxmyJIAlJm.1u', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dec23f59-c84a-4357-9f7c-a06c3435f7d6', 'SP232', 'SP232', null, '$2a$06$IOZw4A7Y0zACOm5SmqKNveCHWt2oZZhDjOGtpw/tTYjY71dVFDQ4G', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('def7e539-69de-4eb1-9c7f-afd5542ef526', 'T254', 'T254', null, '$2a$06$BNMkmREGd1hm8zYd1KRcge1bwst/LASC6m0LHzZbKBezWQO.IwAOu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df073e61-2c06-46f3-b3a1-22080ef43d59', 'TFF133', 'TFF133', null, '$2a$06$WcBWyl98J/2j8vU4xqsmvOaWgdKw4NU6.QNDW2301Um6xsBfeELny', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('df0cb866-c808-47ef-9b73-a4ec579f0e82', 'MTM401', 'MTM401', null, '$2a$06$J8B/PVYEn9MUyTQa9BRkR.slVLcgsFGjNds93LjP.6Mt/4ute4EHe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df23f739-146a-430d-b095-86de77ea3f66', 'TAP018', 'TAP018', null, '$2a$06$mamgQLt6j3lE1t4/H4MhGOl58LyNxrxbT8r11oGbKCq0jpB/PtR.2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df299784-30ee-42a2-85bd-66df1c738014', 'SP141', 'SP141', null, '$2a$06$heHzn/nw/wYLX591jzuGaes/tfeQ47txYRqO1hWsfoACgmamHI0Qu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df2e8177-111c-4bc9-ac62-11e4ce9e3846', 'TFF336', 'TFF336', null, '$2a$06$5drqKcAhEH5.kP3CIQbMweUuaneriB4Dil8/Pq1WJahjhNYP.g/tG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df366aa2-4bb4-4892-af3e-4c16d6f3089b', 'TAP138', 'TAP138', null, '$2a$06$3RIWvy/tNBM8PIoeRNVI3.TxBIWvmOK6ROZ7ICHnr/cGVsPsqITZW', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df38c7b0-feb5-4e96-a91e-d7e9dcf25857', 'MTM420', 'MTM420', null, '$2a$06$hYGl7KqBKMcOvtpPfkbNPu5fAUc08rijdonSeh64N.VYCvzOXoL3S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df515993-9256-40c4-b354-94c3a9c34539', 'SP165', 'SP165', null, '$2a$06$/nNMPPMU8COgTgacp5zU9e229yIVpgpEn/8P5Usq8joSilUEq7e2m', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df87528e-f1af-49e5-8fae-6503e52446a4', 'TFF136', 'TFF136', null, '$2a$06$N3iR8WsKV1.Db7TzzaYzgejEj4tux1WMtn6qL2HAjEVFZLU6LqNOS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('df8ab910-4deb-487a-9d76-ecfd6f654baf', 'TN16', 'TN16', null, '$2a$06$GrnjqQxOdl2tB4lsch0RqulKu8s5VJFmt8HQJ7TjOpPKRyFszwxrS', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dfab36aa-4f4f-4c2f-a26b-3ab3a681efb8', 'TAP302', 'TAP302', null, '$2a$06$S2k0BetxKqf586jjmXS6u.5540XNY2tlX80kN/jWbLYG8mwN7G7Y2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dfbab605-3ba7-4fcd-92eb-e89f2df7d7aa', 'T137', 'T137', null, '$2a$06$UxMqDMa8CMZ1tu/TFTWxoehJXbsXr8ObI4EZ3ij14tMN1B.w2wiX6', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dfd58c13-4ad1-4de3-abe5-b66fdc3383ed', 'T018', 'T018', null, '$2a$06$PiOuLYpRSc3TAx/vGzBNz.2B55ekiGgbjeUEiAxk4pHqxtnFQktBq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('dfec692f-79ea-4e28-80f1-97e0a5e93aca', 'TFF208', 'TFF208', null, '$2a$06$u3XHsNMK2pIsLL8tG/Q0/e1DImdA9jZIei.cKWiYMz0hZbC3YV2Uu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e015cd5f-c4dc-42b1-8783-6eb0066c29c5', 'TAP228', 'TAP228', null, '$2a$06$OINvZv/zIwEAsdkUHaC/VOg7d5rg3RbIIwMSgYPZXXz4rN4arl25.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e0232291-96a1-4821-a834-0f26576551ce', 'TFF199', 'TFF199', null, '$2a$06$GKzsfnej2psMfIFXEglpUOPh88jlJCd/.ugRx7gBL16QbZenZuZ8a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e06370ba-5aba-4acd-9afc-239881d7f79d', 'SP404', 'SP404', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e0ad4019-308b-409a-a19f-88562c0aba32', 'T149', 'T149', null, '$2a$06$KSJjTujxPrtkaa7gtYDs0uhgbydH7Jm1ayuWf0q.rdMqOZQcFqilW', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e0e3a4cc-a82c-42f7-88b8-854f4858bf7f', 'MTM305', 'MTM305', null, '$2a$06$LLo3ir57vxWr9kYKX4NhTu4x1mxvT/jkNC3LQ5PVvqTkoqns8MUh6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e0fa7f13-a71f-44a9-95a6-1b3e68f1c541', 'TAP263', 'TAP263', null, '$2a$06$EGbJynA1j.UJMzAON3JHC.8MB3m7j4TesJyAAXYbNTIN2XEd5d50K', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e107963f-6ee7-45fe-a022-9faaca5a56e7', 'TAP227', 'TAP227', null, '$2a$06$nzdBLGCrjKs/vNc3pB6mb.G/OHU.EaFe/9ssxqPgEz8xe/mkC3o6i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e11735f7-1e10-47ba-9e0f-daadb1d7d144', 'TFF091', 'TFF091', null, '$2a$06$d/OuNpKAQl9CK.u6DC1VsunyTtVDrnsfNjwMG.eXfxmcYFVJYnxVW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e16d9357-914c-4f0e-aa55-d08dae04416d', 'TFF137', 'TFF137', null, '$2a$06$dfhTnVJFWw.7NhMC9V.uK.fSNCVn44I6.5i/VAB2jc67X39wsLKjK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e1917474-d5fe-4d9c-8c50-6b41b2a7e50b', 'SP182', 'SP182', null, '$2a$06$J9EL0hKpP1NcoADCM.H45./PbxCrnPIBq99uPE/0jBrCXjuijf73i', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e1ffc107-dfb4-4165-acc8-3323b541181f', 'T064', 'T064', null, '$2a$06$E6wjVxmyBmIIiQIbBxkRwuB/SxBlTll.cGASef59O5u2Qg8m/B4lu', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e2037f3e-d8f5-4697-96be-6c6562ba7e5e', 'TFF355', 'TFF355', null, '$2a$06$7ca6tnelGjugq70Bzy7/PeL8jvUEfZvgMlTHg/blT6U4EeySWflg6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e24c3b78-3144-44f3-910f-03e0c6dcbabb', 'TAP270', 'TAP270', null, '$2a$06$kjJBrv8JO.DfjXqvaoSvEuFrpPrp3m/jk9xKsiBW/DsHGEaM7yIaq', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e25e74b7-f106-45e9-a844-3882fc5dc27f', 'TFF109', 'TFF109', null, '$2a$06$owd/KmrKcf78GB/FqKzeGebJXX5kGVGyOCLrgVDmpzd0oISieem5G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e273a080-04b9-400b-bfe5-43322ab4a218', 'TFF283', 'TFF283', null, '$2a$06$ATE5SqO9Gjktalp/k.3Kzuz5fodZYD.HwlHH0a08Be6YrJxFi/Dlq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e279f654-f97d-4986-9010-f22f349ce546', 'SP366', 'SP366', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e27aa349-92d6-4fc0-aa88-5bc32db5516c', 'SP398', 'SP398', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e2a7ad58-e86a-4dcf-a53e-6aa61e2ee661', 'TFF087', 'TFF087', null, '$2a$06$Hu9A5md7zsH4jb8qr1YlGejhWjDERCk4gg4VzhUZBrON87p5.rFYm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e2e71397-e8ba-4f55-9eef-a27890e5cf07', 'TFF224', 'TFF224', null, '$2a$06$0TNqO5y4hyvC1B8ViQzEneFCUp6daBWWlvQqBFAhuUlggBFtx9FpK', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e2f077a2-b202-4f4e-b5e6-824e15040385', 'TFF029', 'TFF029', null, '$2a$06$gUHJyYYm1khaSSk9q1O10.lhuis8m2NEBYrvC1A65OxeCevxoKsaC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e2f490c5-543e-48ed-b999-0e28e2fa38eb', 'TAP001', 'TAP001', null, '$2a$06$MgL9qKO8M0qMdJlrKInVJudYZl5AcREiO..Tg0.fgHPGaQY7cBMY6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e326a03a-0704-43eb-b770-bbc2e7876351', 'SP346', 'SP346', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e33e4be9-0a58-4a04-8c76-c802d1fef936', 'TAP148', 'TAP148', null, '$2a$06$IIW2/.N5LXbpJ9iBtyRZz.qcOg1uT8MTmD44l5WZ4QASjLPUoef/i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e342c73b-11cf-4084-adc6-6bfc52952dcc', 'TAP315', 'TAP315', null, '$2a$06$zUt0yGFwxGL34XJ0q02XUeHB2Gvob3uxAnzwpv5CG/kgcEggww.Q6', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e35c5306-a399-48c6-84c0-d6264fef6c87', 'T234', 'T234', null, '$2a$06$M2FgP92.m6eT74oDzXGV1e0VVqkk5JE2DyU4RiMRd.lsGo1osbdJC', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e3a92e43-42ac-47cd-8ec0-27550042db4f', 'MTM426', 'MTM426', null, '$2a$06$fJvjjQCBNdYmtU/otOziSupHNcWfur9FAjQhiy2r6obDuqSfS9hoa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e3e7de79-d120-4222-948f-da6b1d85222f', 'SP475', 'SP475', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e3f2d5e7-d2e1-435b-9173-6d707830a2f2', 'SP151', 'SP151', null, '$2a$06$xqw4vcNa.EuQPHBIGha0Be8e0tCsgKz6LXHl1ZwLZlg7m/OTTQMQe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e3fd43d2-6728-4f45-aed7-c6af041e43bd', 'TFF302', 'TFF302', null, '$2a$06$pdjbHbGUMVXaehtpWlX4l.F62Tt8omv/9wZ5HIk0iX6FnRRpjjFAi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e4000942-ad77-47da-882e-1aa07ded19ee', 'TAP303', 'TAP303', null, '$2a$06$da0Z1d/HekipU6sd1uDCwuLdoxpcYYjHgJZ23fx/H1EAIdUPXSKK2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e4a4c315-7bd2-4509-b61f-5c74056cb113', 'TFF372', 'TFF372', null, '$2a$06$IiQyFJ/RL.D7kyh6wGrFNe1p/UMvKll8CTvTdPe8ayuJVzktmDvcG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e4cf26eb-a083-4d77-894d-6307a25edc50', 'MTM338', 'MTM338', null, '$2a$06$SPucj7tL9x3lCOMzvGjHvOX8VSS4jht2Doc7AXVB29q41sAn57M92', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e4f27508-b604-4202-88ff-a46466f8b9de', 'TFF057', 'TFF057', null, '$2a$06$tr674xSPmwr.KQD7mtXj/e9LdzSnUcQkPzzbKN02sTg2yTBn4WHre', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e541b890-79f4-4c46-a22b-266428fbcd42', 'SP464', 'SP464', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e552dd92-d6eb-4fb3-a4dd-65bb022b2756', 'TAP284', 'TAP284', null, '$2a$06$q8Ybf9DkfoEE/pdzXORLZ.MEDnpBva7MTHIMMWue56ZNRaI1xk8JC', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e570ad45-c9ec-432c-a497-3af3d5fdda78', 'TAP235', 'TAP235', 'https://search.google.com/local/writereview?placeid=ChIJm3NmazrvpzsRbbDlTO6OzIs', '$2a$06$69q3hZwzBqHM/8uyircNb.egVIp60ChVqAc989VMHYIHoizfaI1BC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:06:20.209108+00'),
  ('e57b4796-0bef-4277-b18b-1d116ceb376f', 'TFF077', 'TFF077', null, '$2a$06$E8d3EXPritjuKfFMTKXc3.CsmZWTA.aEjcPhNfAvEWiVr0jqoANoy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e58820e9-c7f2-4e10-812e-54eca7426d84', 'TFF432', 'TFF432', null, '$2a$06$CMfgNe3EQisTY6D0YkMf4O7yKDUmXpmSZttCG67Mh/AXQ0Fv/BLYy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e598f643-412a-4a4e-ba0f-80eb9a16d8f9', 'TAP251', 'TAP251', null, '$2a$06$FhLDzJ52AotKWVbrcMAJOez8uO3HuaD2StuEG4lHMXhp6MMlEpSSS', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e5b6ec63-8a38-4823-a87c-a6e2fcf7b9f9', 'MTM256', 'MTM256', null, '$2a$06$MXT/YKb03dpKfcLddpcHnOXNGDwSHwzP9NoGl3kPGvCu3CALC2GTW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e5dea291-5f2a-431f-bc6f-28abd393cbca', 'TFF223', 'TFF223', null, '$2a$06$24cwlnyIUK8w/1HBCWFHN.7HZRd8jIQap4JvuqGLAZGi3CA4oGugG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e63d73fd-2e2a-4e40-a8f8-b4e395561165', 'TFF431', 'TFF431', null, '$2a$06$TkirVLoyk6O6aiGDeY/U6O0ncFnJ.X/QPJNKHADUmto/fKvtorpBm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e6805b1e-290f-48f0-b1b9-29970fabab23', 'TAP038', 'TAP038', null, '$2a$06$KsN742DOcWL3o3oqfZqEqu8GB8cGbOLUTJkQbw90cOgl6bs8MYBRu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e681c56c-467d-44b9-9843-7ef1ae0f184c', 'TAP125', 'TAP125', null, '$2a$06$0Hoy9SNq8qNQExFFzgPNtuNGKB9i8zbFnJVZaMKOmhPCntcAA67iC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e6d9d096-2cee-4c31-84d1-6fa666f0c2fd', 'SP180', 'SP180', null, '$2a$06$8Vkz85/ZkwuJb6OvulRo7.30PiIAlDDUZM7UVuMlpfI4Skb.4NOSO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e70e5b9a-cfae-4cf3-8ede-e1d84be94f12', 'MTM128', 'MTM128', null, '$2a$06$puHLzviVHMYmf1ttg8gM5O5MGNvhgh3BwnN77vQP.JboyQYXnKrPO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e7244fc5-1828-4f1d-9b7e-ab245eb53e1c', 'SP443', 'SP443', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e7311fe7-b4de-4b40-b106-5e6d649fddd6', 'SP081', 'SP081', null, '$2a$06$51a3EUhnb4ZLVRf2lEsLnuMePEMhKYdaZjUOOhHuIZdLr6Uu0vo8K', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e74f1f9b-478e-4d90-b498-295032e7d0a3', 'SP148', 'SP148', null, '$2a$06$paS8sKcI2Mc1luLLK45wL.3lolI3PHEq6IgBMBPSO7ZGyn7.iCZfe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e771cba0-ff76-4eb9-a35a-2f09d742e79f', 'SP224', 'SP224', null, '$2a$06$bvNGTO3z4/qdCQ67Yt0CaO51sdh7VgheV.Kgh.6JeRMD/gP9jf8iq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e7ef93e9-caa6-4fb9-a71e-3a13d6b67733', 'T253', 'T253', null, '$2a$06$7W.GC0rdLDUanstVoLQexesUDHJDYlW4FDq1N3MJ4SymDbJLEuFzy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e7f09739-12f5-416e-b840-31f742415a1b', 'MTM156', 'MTM156', null, '$2a$06$z78DckC0/oEm2RDdaOyu5edIQGVDnlKZzMDrpG6RobD7HOrGWVoha', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e811b7d8-7e50-4475-b3e6-10ab8e5b750a', 'TAP328', 'TAP328', null, '$2a$06$jbDsjO50orTIVqmpAxroE.YKuc9RAJ0ZnfpYRn2CH21usPD5GwDiW', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e8272926-f94d-4a79-9b62-0527ca16c25b', 'SP414', 'SP414', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e861112c-ed7c-4bd8-ac64-53b6b4d5d6cf', 'SP316', 'SP316', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e87605b1-c3b3-404a-9d93-8fa2b2b3fdbc', 'MTM193', 'MTM193', null, '$2a$06$H8hMHXsUza5Jv1O7V7mMCOQ8nXgE.J/yIq2XgZyTDMRIrU.V4uQja', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e89d01d4-c3a2-452d-9359-0e332d512a60', 'T003', 'T003', null, '$2a$06$J6G64ml.YuihcHLcZ1aaYuiytemP7YbUTPyBGv7POVi6RX5sD5diS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e8c8e1a8-f847-4a38-a3ae-042d3d97f3ed', 'SP317', 'SP317', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e8ced081-bce6-4147-abf7-c2531d0d3064', 'TAP338', 'TAP338', null, '$2a$06$b4WuIcrJjt7Nczl5xRhSJugfSSBc7I7yU8xBuWp9cL8EdzTgeeb2y', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e8e1d2c5-d5c7-4961-9765-24d30c6310ad', 'SP235', 'SP235', null, '$2a$06$secq/oAGgQM9.DeRQI6DmuDHEtSOP.k3MxJ4nrCVXM3c/v7UEiTrK', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e8e3b154-a00d-4f57-b44b-41b5a616a8a8', 'MTM234', 'MTM234', null, '$2a$06$4WXf.YGUCGaG/MFFd6cLZ.z4pgTYIOxPEzoA4/2geTpWTDlY24JTi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e909a701-6d8b-4545-81f6-e11605a72b12', 'TFF426', 'TFF426', null, '$2a$06$RkJb52/eaHw4jhypyFxCc.l3tNN9nKx88ryG1t99cvTSml3MKliRS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9469ef1-76ea-43cf-bf95-9c63424376b4', 'TFF449', 'TFF449', null, '$2a$06$yUr9gW6ZtHk2SDzuQNLLnOxmKMok.eSnW4/MuZzG8wo/9RVRK7zN.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9553e82-de95-44e2-aa2c-3aec027ebe90', 'SP428', 'SP428', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('e95e06f1-fac3-4b00-8101-fbbc7ccdc535', 'TFF324', 'TFF324', null, '$2a$06$uJtpzbQ258wp41yc1LEty.VlMAduqabn438VDY9lS6QSqVxhTqG2G', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9690dde-c871-460d-99bf-ef2289c9c5a8', 'MTM357', 'MTM357', null, '$2a$06$RBTlQP3.DNA.1/AP2mlBMuGxZG2JpCTVkDtXOSjeLivE.h4HzXDxq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e97aa306-2951-480d-9936-c31945b9e0ea', 'MTM299', 'MTM299', null, '$2a$06$RfMR9i3plE/.JmY0mCkm6OYYoJm0JbSQSn81CUxJMz8cnPXDy6Lea', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9854dee-30d0-49b9-b0b1-446b50f95c24', 'TFF405', 'TFF405', null, '$2a$06$zOU5KyhnDcmWwyQtM.84m.LtIabvkRBti6OJAWWfSYF0fAUylQQS2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9bb7e1c-34ef-4436-bcb1-2c2678f1eaea', 'MTM391', 'MTM391', null, '$2a$06$kzeaC/xQfyHISb1hwgVJQOrQSN7W2gq/M/6S5H3EXfnFVHKH/0qPK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9bd8adb-0956-4161-aa88-54de7d058905', 'MTM304', 'MTM304', null, '$2a$06$1oPLiqcfMXPwkW5JmQZRPu23CrxU2L0gSiywInTEBxXQvd6iq.PmW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9c5d9f2-d50b-49d2-954c-cd525dd1bb87', 'SP015', 'SP015', null, '$2a$06$cWOBqm5lzOAfUXMlRkp5guz9yyeYfPDbWLxao2pcJvvPBCvX47vqy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('e9f84db1-b015-402f-b280-4bb7ec053f10', 'TAP221', 'TAP221', 'https://search.google.com/local/writereview?placeid=ChIJddPu39jrDzkRK0KwNXCyJq4', '$2a$06$vvbUJVcNUzvIB4gCoiiU7e5v8NBqxFsyo2NZEITVVlNukmPfDZBI.', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:56:03.366276+00'),
  ('e9fb6da2-75ee-49ab-a0a9-c5dda8f905d4', 'TAP209', 'TAP209', 'https://search.google.com/local/writereview?placeid=ChIJ-_sMifbrDzkRso1rr55WIQo', '$2a$06$PmhPDI.78nmJqFx9f58B1OA7iFa8mKRst7t560uUBeLL/QWGyn0tO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:32:36.581724+00'),
  ('ea273436-7787-450a-b401-e83028403ab3', 'T199', 'T199', null, '$2a$06$6lV/YKXdj6vwWuCTgnPtruKSX1CAqO1rxsobtjjvGfkKqpVuU8q7.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ea2c7dbc-fba4-41bd-b9c1-6e64ef20a28a', 'SP008', 'SP008', null, '$2a$06$/B9KehuoJpDV3v3MCXAhFe2aso9.EnQ7Jv3omYZXHtMJCpK/LEhJ6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ea30c425-541d-46ab-8323-c501066301d0', 'TFF266', 'TFF266', null, '$2a$06$kk401SRd9qSUeQUM1W2AR.BlM4rzv/B6MAcuuopxXtHaZUC3KBEZi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ea516f9d-8b10-4205-bd3e-74d0fe8009df', 'TAP289', 'TAP289', null, '$2a$06$Zaagru1vJl2iXx/RdhMMtOk/aPG99z3jI1q17avswXsI8T18Yviq.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ea628212-38f0-4763-9f82-e626f141bcef', 'T147', 'T147', null, '$2a$06$dg5XIdJM9EX93/t/Lm9X/ux5XwSEE4/eQFocSWQH2MvORojV4lLUy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eac1854f-7c98-40d6-a010-f13d5e53b0e4', 'T298', 'T298', null, '$2a$06$10dsaJRGdu6Q7meURNPsFuYynjPebgDs/C1ElozT6VlNCbimtyU22', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb0f3255-aa2d-46a6-9b48-63203f310d0a', 'TFF189', 'TFF189', null, '$2a$06$VSBIPfHStjegeRf6gtpIyusiqhj1cyu71KS5fyEc/j65.4w2Akj5a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb0ff5e0-3270-4dd1-a446-2316c5857980', 'MTM411', 'MTM411', null, '$2a$06$n.ZopkoyK7jFWuLrgwGJhuM/U2Lrlk8YUme8TiQqP94MQVAFBCLwe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb4becd5-364c-4198-822d-50eeea3f52fa', 'T189', 'T189', null, '$2a$06$NZNo4Me57Sa6LIQ3p0LGBO200WYzTW3s502UzzTAqPyPfVOoNsS72', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb680749-a2b8-4b4b-8c63-a285bd2af530', 'T090', 'T090', null, '$2a$06$vQWENVC8.QMRHbjvweek0OD/JyezDGg.oTVyLnz5xp/2jLyF4oE5W', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb6da484-ff89-4e85-9506-fdf0a0f004aa', 'SP176', 'SP176', null, '$2a$06$zwQ1TvgohDR6CyaDxr3R.ORuOR.T1aGtvtZgrCfBoFqFeb.lIi.Ua', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb7b727c-bac9-4e32-b391-1b8b31b04787', 'T252', 'T252', null, '$2a$06$JrRms0AXznDeqZdLjTZttuCPUnsGqwJwlEIRhxhXvLQgWdMNZDvZ.', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb82d4ea-e2ff-45c1-a161-8642606db539', 'TAP267', 'TAP267', null, '$2a$06$Z64K.izhaRw/JkXaIKe7mucs17OSrIJehgKh46Ep6w0ieZJQrscve', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eb9248eb-3ceb-429d-90b2-4bbc410e718f', 'SP460', 'SP460', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ebb5235d-a5ac-441f-aee5-a8502ddb908b', 'TAP200', 'TAP200', 'https://search.google.com/local/writereview?placeid=ChIJqS0yV5bvpzsRNscKh1mQ9j4', '$2a$06$dNML83u7KniZ4tTpH55NVu4jg7TacUgxMlzePQh.AaAaOppKCHy0q', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:28:05.569687+00'),
  ('ebd6090d-6aab-4a80-a8cf-8d0d73d9fd87', 'TN12', 'TN12', null, '$2a$06$6szkJCt2VGtKtVo2ieqkAepv3gdoCPCLpyQmEmoDQ16iBGmvmVgMW', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ebdb78ee-94e1-4f51-80fb-c39720d9154f', 'MTM189', 'MTM189', null, '$2a$06$O4A5./E2D1xl/AwZQiN8vOcKN0eisOxEPWvl0EgZ0Y2VxB3paPZBK', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ebfe9a05-63e4-4227-9171-94c03311cec0', 'TFF471', 'TFF471', null, '$2a$06$F1uHqgEDsxtgN/CL0B07LO.q6fJAzOpztgcGcehQgbG8rfJz7kmR6', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ec25029c-1cfd-41b5-8942-84ed371b19d9', 'T238', 'T238', null, '$2a$06$Ti5MpwsB5NGW0GMnCpuQ0uJBBVyQlvr95h1.7DnqJe73MI63pLZy2', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ec5c1a07-afd4-4094-ab4e-c0d9e37b0bfe', 'TAP133', 'TAP133', null, '$2a$06$LsiTcaxINULAkpRJEYP21ueXqUpLykVx5Hz5HRST5Rr1Jcn1ISvtm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ec6327a4-9e19-4865-aadf-4e651c7c9fb2', 'SP341', 'SP341', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ec687cf0-14fc-4ae9-85ca-c105f95042d6', 'TAP354', 'TAP354', null, '$2a$06$CVuXBKnRwyHEQAq8jmYbkOHeJd1KcnO7kuTSHXFhOUnvujn4W21ey', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ec81976c-04d3-4e04-9e33-c3aa9d8afcac', 'TAP276', 'TAP276', null, '$2a$06$hSMDutXFJ72Dl8ZvIKk.8.iOF2jH3VMSR2u/M2W2N7lESJqDU80we', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eca67118-07fb-488a-8fcc-6c2d31e684fa', 'TFF074', 'TFF074', null, '$2a$06$au4WNRO.QbY3/U4bpFXIr.KEuwaAVZwjQPZW9uw0f9tA6pcHhdgFO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ecccfdb6-1c0e-4f39-9c28-3a6e77c2342e', 'TAP013', 'TAP013', null, '$2a$06$nw5nncKjGuHP3CAg4FakiONq6mcqlm88aPLuTEMfg9HInuyLm8.Sm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ecd89ced-3f1a-4728-ad92-f8fa0b55e927', 'SP273', 'SP273', null, '$2a$06$gP.tXM99ufY1PBy/HAGlBOmQhiC8qBDcsmp3XmMgnt5lBJnmn.UOm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ece3daa9-93f5-4d85-81eb-c235f109ff4b', 'TFF039', 'TFF039', null, '$2a$06$pnKYR2lelsx.Asb/X9zcfOBchUvxMZCbkDSyY2kDrhoaDEM9yQEAe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ed00d246-29d3-426f-80c3-348f7589ddab', 'SP281', 'SP281', null, '$2a$06$5rNNVx9hn/dGg/uJrlS7KeMWHhZ/ZwvrtR09eOorvgrMwLRTZ/2yy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ed2f8e47-12dd-4e2a-a115-a8bccf1857fa', 'SP169', 'SP169', null, '$2a$06$ieZzJDVLEPRDovmp6UV7O.86ovYpFf05n6hoeZlneeHpuJQHT3JEu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ed44b1ec-db92-41dd-a244-85d225430f5f', 'TAP256', 'TAP256', null, '$2a$06$6PUZAqemArjq8OqXVugCv.bKcM6qsS0FQ/y0oJi679FGtN9nYpnH.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ed5a6464-f223-44e7-b4c9-d3dee7a40660', 'TFF368', 'TFF368', null, '$2a$06$OPFWUARhEzBLG4JFU/WM0.uxUXYMSv7WUoIw2Bcpm.uvSZwuWP5Dm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ed78f757-e455-4e15-8020-9d85ed13b7d7', 'SP489', 'SP489', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('eddd998c-51e8-463d-9031-34f8aa920fd2', 'TAP051', 'TAP051', null, '$2a$06$NrV2saCe2/RcA7E2K8ZPGOmlfom24dDRXxjrvjuqKSs/aU/0jylmq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('edeb2ac7-366a-48ba-9ad7-b5791cc873eb', 'SP036', 'SP036', null, '$2a$06$dk9jIeJ2J9fr9g23ejZdO.aUhS8ZL5K7oQ34hVSvBIVAnrREigRD6', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee1dbc60-d443-4eff-a12c-e45f1822bd27', 'T292', 'T292', null, '$2a$06$PhyD1GDTpza4FeirK/aSzeYsdzMJavmc0y2UxQ3KqSoFcHwM/U34S', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee228d0d-edd8-4636-b655-2eb5682780c2', 'SP272', 'SP272', null, '$2a$06$9QyUxvdpMeQ2e4hjJxuQhuNVDSOT4jlPsJOiMSrzGSInJH8PqVVtu', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee54176e-95b5-475b-9904-661eec0a03bb', 'TN01', 'TN01', null, '$2a$06$FKCryzwHmTadb2Fr6YdSlu.nRtyHiXwPd7mtP8f4mnIZxZe14WX9u', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee551dde-c099-49c2-99c8-c08ba917d72e', 'TFF134', 'TFF134', null, '$2a$06$SW.phBSd/b7aSzw1WYC1LOsGqotZMlXRoh6XusCX8u2GX3lRwq4ie', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee6bceec-0312-4bac-baf2-252f3e7a5bee', 'SP140', 'SP140', null, '$2a$06$VsOWp.PdYZMdumh1PT6SfeUn2qtcU7XfT08RXzDlmxGZnlTvpnWXO', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ee6c8d78-361f-4f07-9fe1-29886abd73cc', 'TFF264', 'TFF264', null, '$2a$06$WMWB3c8CK39HoEqcU5ZAPexm/q3ugatNccePY9Q8KZJjTXBNCNCPm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eeb46062-7445-435b-b2eb-5053387acfa0', 'SP231', 'SP231', null, '$2a$06$1WTIbvhKQueUDTEqQWUreOHIHH2ZlNb8QqkWgCWcOG8SMlGbUoGOy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eeb766ab-be39-4d83-b45a-26ca2fd0f3fc', 'SP425', 'SP425', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('eec72773-4fdb-47c2-896b-bfbaa3deefea', 'TN11', 'TN11', null, '$2a$06$eJU8OkLbjI2QuRmbiY8rEeNxfmPAEgmeeE7jyFcH5gkyP/H2apGOa', 'active', '52018480-1af0-463f-972d-e815d8b1e593', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eed83a77-1ab6-4068-ad34-7f83658d3bac', 'SP446', 'SP446', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('eee78cdc-225a-462b-b828-ddb818491908', 'TFF196', 'TFF196', null, '$2a$06$hznhAYIB/QS0dhov5Od8nu2u8S8W09y1I2NTCK2XjPeg1yM6FJElm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eef04f22-72e4-4d4b-8380-9ef85ddd1fc6', 'SP229', 'SP229', null, '$2a$06$Yg9Y7C5ist6X3mkZar99j.QQBXHGX5PNpWgmL6ev1jJaSEtkpmGke', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eef57193-2ebe-433c-8dc3-cb40ef7831a4', 'TAP280', 'TAP280', null, '$2a$06$IwVSJo4d1prXvpWOBibQq.nK6sInvNiUbw5uOZu3jB37ioqY93brG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('eefd3a88-e1cc-4802-90c6-7ba8d30ebf34', 'TFF121', 'TFF121', null, '$2a$06$XkFvtBMrbG4Gu8zWclhyzOxwTrPdUErBBpTM/MTDzDNidXU1xaUPG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ef0054c9-bb9a-4dd1-91b3-49b18f66cdf7', 'TAP382', 'TAP382', null, '$2a$06$uL7w12bWSndeC45XaJ05c.bFeMmWwtxmHQKO54JsSZDvvZyh.OxVm', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ef1d22ea-9354-44bc-a969-964d468a581a', 'TAP106', 'TAP106', 'https://search.google.com/local/writereview?placeid=ChIJwcIy64bBwjsR4-eB-pdzTOo', '$2a$06$/b.jpSjKad1qmf3PabbDR.YxiG9kKSEAaccw1oyteJek3gOyb/XJy', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-13 13:05:46.403192+00'),
  ('ef466441-8124-48ca-96df-676332eb3bff', 'MTM302', 'MTM302', null, '$2a$06$VPlQcQFVNhYWekCgFh9bxOlUd4WrTcJAGpwh2RSF6hZs/FFLOpKja', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ef48c58f-ca27-4e49-b14f-da5a281218f8', 'TFF250', 'TFF250', null, '$2a$06$6KtRI8LQdxar1zKcF7vOC.fUMHY8tvk/Lhqe40lA.ziBN9J7eXPA2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ef80cfa9-afbc-4967-acea-e77e7fc34c3d', 'TFF098', 'TFF098', null, '$2a$06$m9jpKZWGr5aVQlv5IV.z6Oc.1BFsUij7dDd/MsEILXiBZ0lDcJy1a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('efc58c90-f961-4dae-a736-bf580f8a3cd2', 'T201', 'T201', null, '$2a$06$P34OJoU3WNREyp68sVG2mO05PqTSQ/TffwA5WJ2xRpWf8P9lMBn7C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f071b4a9-0c01-496b-bf8f-387ceb583e92', 'SP005', 'SP005', null, '$2a$06$PqKMY7mgiNSNTB1tY3hqXecHQgnAnTK7arcy31GdFtzc9FCkrd/ju', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f0863472-b14e-4581-b2aa-f94fd6d98de3', 'MTM208', 'MTM208', null, '$2a$06$nSFfjaRD4GwjmgJsciP3nOhud06qCd2qIGtFkuJ9dro2G5D9b0Cu6', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f0a55890-0b19-4bdd-be3b-f0caaa1b1156', 'SP237', 'SP237', null, '$2a$06$yuvPUkJYzxtjO5ZLoLPPfuHaKtQ.pRpFNqQ/uebkrNAV0p3F/6EX.', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f0dbd3d3-dfda-4fc9-93d3-f735d66950d2', 'SP402', 'SP402', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f0f08252-1142-4d27-bdb0-0fd96dc9a519', 'TAP229', 'TAP229', 'https://search.google.com/local/writereview?placeid=ChIJrVrSW63rDzkRK77GS33fyoA', '$2a$06$uJdMZEsaqZ./yEAQ881JSeDCuHvYTassUN9RBxnFZlRxAmgYYd2aa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:39:58.173621+00'),
  ('f0f3387b-8e9f-48ce-96fb-ef3f865f65d1', 'TAP386', 'TAP386', null, '$2a$06$sVC3XmnNM844PjFXJNvPDeblo/PulSS.UPABraChNDYgR8AR.tflK', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f129649f-be32-454a-a74d-88b2dd2abd4d', 'T118', 'T118', null, '$2a$06$DIxgWEAJHF0.jNaaX4SFAe8OvUWFYGAYs5PUDVlXi8yhjl5D3Yp9W', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f181e6fa-359d-4f10-9237-666046d4db03', 'TAP045', 'TAP045', null, '$2a$06$cU7S3x0MJQJhunPMpg9jMu6YCSaUUaiiRMPb1ctCzIWWvMqQ2NWmC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f1c09fd6-896d-4604-a7da-741295cf72ed', 'TAP301', 'TAP301', null, '$2a$06$7P8NAaJoBR.Cxsg/cEDpHOUTsovWryrolxzblkdt7aDErsNye5mX.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f1c75264-ea87-4d46-bd9b-3167ce854d4a', 'SP380', 'SP380', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f1dff719-ebc3-441e-823a-5993b68bf6e9', 'T257', 'T257', null, '$2a$06$mK6TiHhu66a.Fo0oKUzhFuOrITjOlzjhWC3lXsjMS5EHVjIEnYsLi', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f1e394d5-87a5-4116-a909-e56b08405bae', 'TAP381', 'TAP381', null, '$2a$06$9RtBwq7u59DHB1ZSHg9.Lu6ICXwNkLzqnMyifAlrgKMb59Yr74om.', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f1f55ce1-828d-43e0-a8d1-16ca92d9ac8b', 'SP270', 'SP270', null, '$2a$06$C/AGK2b7l.SyqzvqPY07y.nbAFnnkxWpegIMi4.1Ob5WG5NbSmIoC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f22d5a92-840d-4682-b8ed-73b4a9b1bfc0', 'TAP196', 'TAP196', null, '$2a$06$ztsrSt6LHXT9AqFM8oZ/AOoAlux5S5GVmDIIZneZu2JciFjMRYfUS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f2368700-e586-4dfe-a595-97d1e680615d', 'TFF123', 'TFF123', null, '$2a$06$87teKYmOU9kLRYnQFvcL9..NRMmdRIwEJDJede6Wo8MMT1cnJV7ty', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f24acaef-db23-456b-a0a6-dee392a007e8', 'MTM432', 'MTM432', null, '$2a$06$Cm4pPxibrSXPjLmYJhWiWODWGBqMjpImHnNtJ5dPHV9zGMRf4z.wu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f25913b0-d5a4-496f-a87e-a46aad40486e', 'SP064', 'SP064', null, '$2a$06$Ts4gq.aXck5d6V8X1UB40.ZouPgwjNTccGH6fb26OMlFHaNd13TXS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f2609be1-cc56-4e75-9f39-e96f548704d5', 'MTM367', 'MTM367', null, '$2a$06$KdE.xpTKMC6TJaAF.7p2cO71rEsuAFe7ng7RAfmuD24O2mMyKZzj2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f27b117e-9d07-41ba-bb29-53a3577e729b', 'TFF370', 'TFF370', null, '$2a$06$Zw6uCiZJtPNdAPwfc284eO1hqMtfM/JDQ7PnCp3WbYLrcSKJ6RI9u', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f295ed58-ca0b-48f6-8e72-ec70fe627344', 'SP123', 'SP123', null, '$2a$06$9csA0lCk85NVHibq/k3qY.crZawWwg.czLoGqSshlqjD1pAr2bWmm', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f2a54bc8-5a71-4487-bebb-50004b4d42a5', 'SP435', 'SP435', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f2b30bba-c5ff-4ccc-a0d7-bdb4845ce451', 'TAP015', 'TAP015', null, '$2a$06$/DnvNwQ7ufPhfbbzeZzwietTfS1JeVysXVz6YJMz2BWUhWHXtC1S2', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f2d0231b-d9cb-4ca7-b3e4-48cbe4b0ab1a', 'SP021', 'SP021', null, '$2a$06$2b1aJrMa9eQNW8tCQJCaLe.3IOSWDg0xgulBTLwO2yc.G1se5Zhbq', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f2d83eef-0972-49ca-892e-7b5522b8322b', 'MTM295', 'MTM295', null, '$2a$06$zP.VszlXdHb8ASkTWdTOOuy7SsU9KSjIKMYsBvH8b1hkScFDYOwaW', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f31c8e0b-26a6-4320-9fc9-be6bb26af7d2', 'MTM321', 'MTM321', null, '$2a$06$tFArcXxupuzJ4HksWrmXD.vcy61lvbPXj2tJOex13Ul3lXJcJRXpu', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f359b436-cd83-4f5e-bbcc-8baa2576e641', 'TAP195', 'TAP195', null, '$2a$06$Ym2xesjoWpW2WqTp4noFxe5Us5iT7D9fvbrQm16BqRCo3YAB07t/i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f37b9b57-8835-481c-9f2c-29f5434807c5', 'MTM290', 'MTM290', null, '$2a$06$lGjSascljYx4W9EuzT8gs.8hz2Cadis/R.OtWOFTpq8iwpXQJtwAm', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f38deeda-df0f-43ac-b9c4-423e43aa5c5a', 'T078', 'T078', null, '$2a$06$HJFcdHJnDJeDbnnwBHPU2.eivrCEeIPm7JLqIhcg7WTMNLpQsFkCm', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f3a60515-cfba-45fa-a881-0371678434d3', 'TAP143', 'TAP143', null, '$2a$06$Onnm3AKh4cB1n5kBpMR..eQdzAHSxvFet4mdEIivnnHtRg5Jkh4tm', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f3af8014-f3cd-448f-9eaf-4787bbbbe521', 'TAP176', 'TAP176', null, '$2a$06$DPmrYEI9PbtnM/uFAIAwbuBoyxTjXw7qvtQ4Q7Th2IpKMyvxM4U2G', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f3d3bce5-065d-4104-8fb3-b51d1be9c42d', 'MTM192', 'MTM192', null, '$2a$06$MefeMxwI5391TWpTsQAsfeRzXt/77bnttlzunTo78M2Ew9egdRdii', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f3e114ae-af57-42d6-8301-5a45a7553721', 'MTM345', 'MTM345', null, '$2a$06$NLJs2O2X8hONnRAAgjOuUeEbwBsixv1TVxgV66F5sHjwOdmRPA5fq', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f3e1d1ac-2db7-4bd8-b2eb-ffe515596070', 'SP292', 'SP292', null, '$2a$06$TmIuz3slLOxweDtbBeHVxuOH3s2atYLlEYi69n9jLYlRUokpFoyYe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f40e5c82-608a-4d39-a838-1b243e001dec', 'TAP400', 'TAP400', null, '$2a$06$pu0OLYtvuU/LwpgYXLQSf.lGc5bCR/ZIwqdRlliYgkJKY8l0zad0m', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f4749804-aea4-4ab9-889a-af8780c86736', 'SP463', 'SP463', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f47a004f-50f5-4b66-a66c-3e715e1d8502', 'SP465', 'SP465', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f4a712cc-2995-40de-b927-f2aeaa1e2f67', 'TFF147', 'TFF147', null, '$2a$06$29UYuCNjRwN8VKZL4lg5yuIkFqjA36Hl25a14qJ1fj0tQz8P4GG7m', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f4ebc53d-6553-4ade-8f95-508a5de40db8', 'TFF220', 'TFF220', null, '$2a$06$.7FlQNMdzt0IgESDvRhq8.uoA2xNTzCvN0OaY3aOOpRzSjIiXkIqe', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f538d940-f40c-4244-a720-b5ed5ff8b0c0', 'T152', 'T152', null, '$2a$06$usApWTzlzdgK2rhJGnvFJuoIZUcgqb594DupMqV3l9/b4lbupvBMa', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f56b7efb-ef7a-4618-a6cf-25cb908b8105', 'SP108', 'SP108', null, '$2a$06$qcQGjBI9M.aIWPVpZZDPKeyA3oX21rBAX4PvkHCaJVXoLkq5Lrude', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f5754900-54bf-4710-8636-386f0dbe1c68', 'MTM330', 'MTM330', null, '$2a$06$j.vWVy0igAHKBtLVufXOAu06.MqRdFCMX/4O93De2jQzVOxvKI/ji', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f5bce439-5225-4c8a-bde5-b5800e67f7e3', 'MTM273', 'MTM273', null, '$2a$06$J039l3vsuqtiuT6T2lyzU.JUNrRemz8G8iMP0lfh19kwONkaRdpfO', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f5d9985f-f788-451a-b13d-7363d275f9e5', 'SP147', 'SP147', null, '$2a$06$LKoIGgsTGPhpvYObvXwm0ebt1QD8F3IR4Y8d712f/rUHEL0VDyWBe', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f5fd0b51-70b9-43ef-86bd-d7b4973b5718', 'TFF435', 'TFF435', null, '$2a$06$6a6KPBVLiWn2NSbZHFYd8uGS5pES7MPRakInBZue8TO6/U7XXxzuq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f606cffb-8bb4-48e9-89da-57eecdac3c45', 'SP298', 'SP298', null, '$2a$06$jXE/8f9DCl4AmkfIfidV.eiNSUBXkfzDHPKgnhmD4qJnjmM95D86O', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f62eaf1b-fbbc-48ce-986b-0ff3e13ccb8b', 'MTM343', 'MTM343', null, '$2a$06$qTMjEDMfwLXSWGARvLAZI.6Ga9RqOQ2O6Wd3IHjElAV.c.e1CrrGS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f62eafaf-0abb-42d6-bd5b-c5f4aedaa46f', 'TFF106', 'TFF106', null, '$2a$06$5CZYHp7106zP.sH2w5Hp4.qrdwA/ZIkWddifpfIJzEMdY6Q9SxlxC', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f653ae1e-60ad-4697-a0d9-a533e274a043', 'SP295', 'SP295', null, '$2a$06$S.6UpjY42Qb2vV.LT.LEYe8UlABCGdJcZwCU9ug.lX5iWUQDo71zy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f67cf11f-0e4b-4e40-8024-35f7485c11e3', 'TFF099', 'TFF099', null, '$2a$06$RI3iXS39oy0Z.TnCHoBWbuvJPizEa2TEaesyvtBrSM6dI9PlDsSEm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f6cff0d8-cd96-4e9c-8526-6dabcdf005de', 'SP131', 'SP131', null, '$2a$06$xwLqq84iTobEKYYZWgEeT.ml27brDww9O8E73fgew7L5ILxYmoXEC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f7371c50-518a-43b0-beaa-57e3dbb3fa94', 'MTM413', 'MTM413', null, '$2a$06$KvGN5ruDWKSvNbTKQavSQOJSsIfglcX7wZb//yhapyVsIaYtBWD0O', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f73cac16-8508-4432-a930-0b8f4a786289', 'T290', 'T290', null, '$2a$06$kx3wwvziXFg679WDxQ4tc.pVtGcYAhKvOenEsGh7wYHxOYO05C9OO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f74e0f90-52f1-4cb5-adb2-73e07ae9aaf9', 'SP314', 'SP314', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f7527f12-d488-46ae-a751-c449c521b5e4', 'TFF129', 'TFF129', null, '$2a$06$65L6TfssmXfFHLJFPfzhje2jpSdWysd78lN5Cmkhy1XIEHg4Wqc8a', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f76f4e63-adaa-4814-8c6c-0000ca75fd27', 'TFF043', 'TFF043', null, '$2a$06$aRQEPn1FYHjvFKBdFIF4L..vdt5/GPQ77QRLyv3qVXzoLlfSQqfW.', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f78bf836-0463-4937-86f2-f54c161d1c69', 'MTM341', 'MTM341', null, '$2a$06$ejKuxqnYAAQu/KfwEX.fW.aYPYsnaxMPxdYgfzWtQ21ud3aZIBOxa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f7a3042a-fb4f-4174-bd8e-c0dce3002465', 'SP451', 'SP451', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('f7c39fac-a3fc-4331-81d8-613c237e6f34', 'TAP136', 'TAP136', null, '$2a$06$rQr.JZWERE7PdXMtTKVJ5eDYvPGnywPC3qMep0vZFIE8vCrxWeqGa', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f7d4dc0b-e78e-4399-a549-73ea434135bd', 'MTM382', 'MTM382', null, '$2a$06$DPrLNSBeeb3mdYPPApRrVeGR6DiIOAom/bV1816oLPoMAjWFEKfTi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f7f8e961-330a-4549-a181-74a62d5a810d', 'T051', 'T051', null, '$2a$06$r3QJe0rYMx5jckkc3z7sk.QJRaunUiogAUZ9JWdqhrYq6avomKrNy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_codes (id, qr_number, qr_name, destination_url, password_hash, status, batch_id, created_at, updated_at) VALUES
  ('f7fd9565-aa4a-475b-b340-f129aeb5abfe', 'MTM207', 'MTM207', null, '$2a$06$4fNxx4w2LZI11opiqRSPT.akF5l8jJp2jx9FaoZSUYA.R1wIEVB4W', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f839a511-2084-4d3a-95f2-11f3023b9945', 'T177', 'T177', null, '$2a$06$CGSJrk7putfQJmBNMBpJlOQUzdFQNEA2SXvFjDugHh9eo3KjFlMGO', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f866ad55-ae8c-4f48-927a-f6a321a0b515', 'MTM307', 'MTM307', null, '$2a$06$/ULZkgEpLhylbUR8f3vvCO1PPuxkz8SDtUT6sB8WyLBrhBeLWeY4S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f89b2878-13f2-43d7-850a-ed72d922e01c', 'MTM387', 'MTM387', null, '$2a$06$CBbqJ4iiung87JjBrhBjHeXjo8IfMItY4TFucCXh.r0CwYawHNdXi', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f8b0cbde-6e7d-4494-ac0b-400a95159a97', 'TAP122', 'TAP122', 'https://search.google.com/local/writereview?placeid=ChIJ2Tdc7VbrwjsReiDFyecXJlk', '$2a$06$kVNQUHZeumGTTkULkH0qyObqU6UYK9tes92Jmj/nYt6Nh5XjQiUOq', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 09:20:01.179139+00'),
  ('f8bb146f-d1b1-448a-a59b-8ac9b9c485f9', 'TAP384', 'TAP384', null, '$2a$06$K4LR7wW0rjW6pUu/CS4kK.cm0r9LCF61OHFsG7UYcfp41meTxALh2', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f8f66844-a7a1-44ac-ba3a-fa4726fe6561', 'TFF375', 'TFF375', null, '$2a$06$7U8dHd/l85whqItaHKcRgOJgMIoS8vlHdehr8gf3Dsa9bTX487OVq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f90b45a3-1b98-427a-a753-44e94d3bffc8', 'TAP277', 'TAP277', null, '$2a$06$549NoliMeBdWuQAVKlK./ekzxuHGLoEYmWv/2tooiXn8QxejSDiJy', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f9867cbd-ef9c-4b17-b89c-696bec2953d1', 'TAP260', 'TAP260', null, '$2a$06$zvffhLnY6QRrZASBSqfxEeKK94Pt6OJ3LqO0UjaPay5NMtRSJ4QFG', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f9a79c71-a920-42bb-9c65-5f4c339e50b0', 'T245', 'T245', null, '$2a$06$m0NAOFcfETcOLzNGn/nSZOjeFTorxxpHX7NfRTjNjPOMcI4tZpLrq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f9e9dc11-07c1-4d67-9571-59c4f7950a72', 'TFF124', 'TFF124', null, '$2a$06$IklxUaM74PAibcCl3p7NWentxbSv4LOChgk3xGrntZK6S28fBvjbq', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f9ed0232-f77f-41ca-96bd-0cf696b0f5ed', 'MTM350', 'MTM350', null, '$2a$06$jdR3x4KT.sDw3qTPXKUyzuLTFQOrE81vRmaMULkOQqamiP3XucMJe', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('f9f7f02e-9832-40ba-ac4d-8b2ba8933a58', 'TAP162', 'TAP162', 'https://search.google.com/local/writereview?placeid=ChIJtd4HaEHrDzkROpVij76BMPY', '$2a$06$vZYgtk7f0Ht48lpqHHptZ.UwcSSZlXSXfngKd5xL835qkqwNeuUHu', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 14:10:20.334451+00'),
  ('fa249630-b0b9-4ce2-a676-02147ec5cfaa', 'T291', 'T291', null, '$2a$06$ow4R6PE5kOLsk2b7BotJyO4StoojMC3.rw4iu.NGYgFodAfRQqiqS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fa2b76c3-05f5-41e5-bc47-74a07a1abc6f', 'SP085', 'SP085', null, '$2a$06$M6QvCXY27oy.n.TiouVf5uT/O8WnEj3j0P1NGrzosx.v9IkcmN65y', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fa47b102-cc0d-4300-a2fc-98e34bdc319e', 'SP007', 'SP007', null, '$2a$06$Y8FDSotz6yFa87Ny0m8DTOx7CySDiFqkbtbnqP//w0I7Jernvqpwa', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fa520db2-654b-4f2c-af24-10c30b3b2eb0', 'TAP172', 'TAP172', null, '$2a$06$aqeqc2MAUyxA/ElhrlWBAuYnn.SZUEe8DjJv/MK.BDebTtgG0fwNS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fa64de55-4f68-46ba-9b92-46fb3e95039e', 'TAP078', 'TAP078', null, '$2a$06$mO9D0i06awOlYyF7AOQ52OffHsohYnOSK6w4J1flK/NlTyAjuxLuO', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fa83c347-1e16-4d04-addb-4a632644d085', 'SP384', 'SP384', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('fa8e7238-2f28-4933-8e61-8a896b5bb232', 'MTM131', 'MTM131', null, '$2a$06$x3T7IinkB9/lLr8/B/flIOhc2C51MIlBgTj.N74oMtN7hM2u1bG/2', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('faa856b2-d55e-4aea-976d-66fe1a1859c2', 'TAP376', 'TAP376', null, '$2a$06$aJVP9J2m8bKLEn1jUrFHaO4c2HgqikZRyG8nLXg1cIzSVt4.ZTxwu', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('faacb486-b989-4517-99e4-dfcfe5e55ca7', 'TFF327', 'TFF327', null, '$2a$06$uHqKU428Ku/Jv3blT/ToPOADihSxL.p1alyjtbI46utAO0HUs98ii', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fab57eb0-35e5-4a18-885f-4eda97b80240', 'TAP183', 'TAP183', 'https://search.google.com/local/writereview?placeid=ChIJ0TfVe13rDzkR9T9-4IWls1c', '$2a$06$ZuOBcdKtHCzWsA.FBKnbzeARfiaHBwit4W9JmTvYpHsjQXWvyg79i', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 11:48:58.870013+00'),
  ('fac56619-7329-4bb9-87e2-6dbe68789d31', 'T009', 'T009', null, '$2a$06$1FjzBms.W1L8nbFXYJ89Aec5vGrFq46L1znqpvmc28.hdrJuKfxvy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fad1885c-3c0b-4d91-8b84-0dc33b17a3c9', 'T128', 'T128', null, '$2a$06$eGxdp73BtXc0R9exK.4S/eRI2JIWPSTIvH2YBNoyNq4tfn6yHNR8C', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fad9d0a4-9f81-482b-92f8-232b35095d24', 'TFF496', 'TFF496', null, '$2a$06$l1g6SLj.vsZy3wcqyx3kyevL4d1M7uUhD9mBnCDWuytiodcabQEaO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fae78456-3f20-4b12-b1ab-89b6d7e5670c', 'T207', 'T207', null, '$2a$06$uAaC2XKy0ifDAD1Y0Nk/leXbWbA.j8XBoYwJ21B.2Fe5X3Ud6gJdK', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fb0146bf-3cea-416c-82b0-c7129aa2c9bf', 'T057', 'T057', null, '$2a$06$GyfUXlJ.f.8nd/AA.vaWGuUCC4jabbt8d/nENVYEx7ccZNbzkMsUy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fb094074-bcaf-4109-98ce-b4bad0fdeff0', 'SP326', 'SP326', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('fb21c5ca-adf0-4b13-a8fb-90622a9313cf', 'TFF095', 'TFF095', null, '$2a$06$Y26UBJUb4wwYo9eL7Xy9neg4KMeCbxfxbX9JuWbteIsQxqSQj8YmO', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fb3395fa-c238-4fdf-865d-b25e412a1a6c', 'SP386', 'SP386', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('fb863652-9d44-48cd-9d05-4cd7a27dd5d6', 'TFF138', 'TFF138', null, '$2a$06$4vum4vWrCkpfTC5yjMhEZeBSYog8Vu1mhIQ3DfzC1/U/FWxtkA9ra', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fbad9fc4-0aa1-4045-94fc-b4f10443d440', 'TFF056', 'TFF056', null, '$2a$06$qN7ivrQZkCrKc8JmRFUfQ.jwgG.HcG5b0qptPVst/aYlGwZtRz2Fu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc041dbb-ead5-4fc1-a7a3-425ed3177608', 'MTM456', 'MTM456', null, '$2a$06$vYkxiooI/VySFJWOqnPySORUdfKwuUhp36juXZKJnFhQUIrCYBnle', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc1d061e-d8c4-4bf5-892d-b8b19482954c', 'TAP169', 'TAP169', 'https://search.google.com/local/writereview?placeid=ChIJF7PdPTTrDzkRA02ETpkRueY', '$2a$06$6cQNSS.NGH5Gx6bjkylBD.IWeoiObwjn2.fP8g3t/cCTB1rhSHCee', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 13:47:45.17741+00'),
  ('fc4e0e2c-97b7-4c51-8cc4-5d09c52c5789', 'TFF105', 'TFF105', null, '$2a$06$oEJtxF/n.jeOSQOKBXUUluKJPM3u6o1vrMfBPinSpWll68QNQevdS', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc4faf56-f44e-452d-9ce9-defcb124385a', 'TAP146', 'TAP146', null, '$2a$06$DA.UEnSVSrN655b4k9NTpOyAKFqZSrQR1foEZjPdta3W0uXeV5Hj6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc51542c-12be-4067-a9b9-62783ca67efe', 'TFF494', 'TFF494', null, '$2a$06$QvCy1AsGYvbgazgQ6RYoRuCksJfewzrhaRBzPnKXQLEnBgcAdELI2', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc6f2e59-9d3c-423f-8dd7-ece7f87d9bd4', 'TAP103', 'TAP103', null, '$2a$06$kCj7S5dTWWI0O.M/uJF4W.p4aWT56KVsZit21plyuL9bnThbC.PHG', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fc9ec7c9-f0be-4b19-a7b7-81f892fb542f', 'T185', 'T185', null, '$2a$06$RXklzOjEXJMBPd3QuKCSQO9fw1Jk59mCf2caOBAbnIaWo3fMhYUOq', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fca631d1-b053-4c3d-8187-260099593186', 'TFF188', 'TFF188', null, '$2a$06$ZIsmt/GBGUoRw5.t8LLh8.eJ7z9QL66ro23Q2ukRZkScx9I4w/rWW', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fca9c54b-39fc-490b-bde1-022c2ff3223d', 'T141', 'T141', null, '$2a$06$bRvwtzJaeFFn5wdRcf//nOM5O.HPHw3mzBHqhx1mFM1WnWTMjkgMS', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fcb1174d-a006-4c45-a48a-be800422be42', 'MTM402', 'MTM402', null, '$2a$06$QINtgd//yGUWcRkrgLlUquEGnFJz/UR2J3BlvNJwIbheUgBZizOvS', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fce4cb40-e215-4ca3-915c-7e387ab5c1c2', 'TFF467', 'TFF467', null, '$2a$06$ZdB7esvfw9vAf6evp01M9OxMoF144YTurQSfpvajYvbdju5bfjl6K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fceefa46-7691-4b73-be5f-032811778807', 'TFF195', 'TFF195', null, '$2a$06$BiSK65F7JRY5r0K/3zVEL.bsV3bvi/aSNwhUIOKZHP9xdtxRd9OPy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd2f6160-fdcd-40b5-aa08-9ebf33580518', 'SP426', 'SP426', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('fd36cfef-28f4-4865-aed5-5309c7a51435', 'MTM211', 'MTM211', null, '$2a$06$aSLDBD9EojXSKp9U2G7pzOwJRix5b40TXbGf2WGz3gE.v.tGgkb3S', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd4b72d1-32d6-4026-a9ba-46aad9e5d0ce', 'SP122', 'SP122', null, '$2a$06$tQeA0X8nO4lbXZ6D385wsOr0nLf9FJ8AHI7Ha56U8fT3OT0Dndjau', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd58ae4f-6106-4021-91e3-daee80674652', 'SP297', 'SP297', null, '$2a$06$bcgxkpyaFtHr5jjLk6tnSOFu8eiR8wxkf1.WPRlrVTLwW7mBJSCia', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd5cb41b-0cd3-40d1-9cfa-0a6fb5c0c757', 'T198', 'T198', null, '$2a$06$tAQW1YEMMxWwPZ8VMFqD.uROTs7PPjzpm6nUKceTaUUZmzkQqjBuy', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd6e013d-9008-499e-96e2-6475169e1e10', 'TAP053', 'TAP053', null, '$2a$06$HnN4/BXFvOqJmE36n2A8Ku0fYAvO1hfDMf3XnyqWI407icE2NzlzS', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fd70f427-26e7-4e0f-ae84-9666971ce2f6', 'SP057', 'SP057', null, '$2a$06$XvYx5F/BVvZ3e4ujoV5LmeiWUXMHk4BJgIvC/YI6jGnQKgS7xAszy', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fdb02af6-b0f7-491f-bc3c-1275eaef3b24', 'TFF053', 'TFF053', null, '$2a$06$wnU1mOeN/v0PlkO.OtP3UOvhnWezlbmJVM9xMnc9nfdHRmIFt8ELi', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fdc9d6a4-b12f-45f8-a9af-9b4804427057', 'SP045', 'SP045', null, '$2a$06$2zs6k/7ozPvDZDUr7UYPdeHz7/TEGEahKo2a1uGwYZ2EkupPlMEza', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fdcac249-7699-4dc8-89ea-428fa5cf4958', 'TFF298', 'TFF298', null, '$2a$06$X3vVnD458Oh39zs//ocSXe.fgEdnBzKGIJcHHXxIBXM/XMXB9poDy', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fdf590b4-4aaf-44f7-9ca4-08a94bfa0094', 'T070', 'T070', null, '$2a$06$N13HWU1ObZ.m1C4cvo3jRePVRYvvxgQ/AqZxGFx.tihJKvKIaAp4m', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fe3207eb-d4e2-4896-8ee8-b5f89096e870', 'TAP242', 'TAP242', 'https://search.google.com/local/writereview?placeid=ChIJrcb_i37rDzkR11-dJslmcWs', '$2a$06$F4cVMHfygZzWdo2eNakW6.4P7lLxSowcqvH.GvlB9hdwFSq6SGKNC', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:20:23.144053+00'),
  ('fe45b314-9ec5-4ed2-b9a5-fe1dae47fc85', 'TFF313', 'TFF313', null, '$2a$06$5o8vvcYMw3wrrcvt/Jv8P.AN27X0BW1kuU.Hdzr.nEm7H7.S2qr6K', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fe63761b-75ca-4147-b724-c305f76d5737', 'TAP344', 'TAP344', null, '$2a$06$7Lj2n88UqK/OO0S6AHCmsOEsTUl2KOhFJ2.M7Cgh68rnjlfJtYIma', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fe65f1bf-8591-4bb4-ab8c-eb4a36fe9300', 'TFF219', 'TFF219', null, '$2a$06$CzpQbAcQxO1pG79FCx6HseEBno2nVcV/N3Jddj638j6ye/Vs6dd36', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ff12acf5-1c2e-4165-954c-d3ab6300d72e', 'SP042', 'SP042', null, '$2a$06$iqI7Lf.9CS7IrXPVDXE9fOgN.5oL/D8ZyDrtNAE4cjHvcLB4UeDuS', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ff3208f7-39f4-4918-9ee2-b0b7c9445d5c', 'TAP336', 'TAP336', null, '$2a$06$ueWTig.lkNEqPY97ja0vo.F1yKUBn8.WFdsMoa.3vOVZ2Dqhn6vTi', 'active', '854beaf4-248a-4ed3-a327-f5b4a48ae9d7', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ff408846-bce3-4703-95c9-e3653266e195', 'TFF291', 'TFF291', null, '$2a$06$6JLnHaIB5pJB9vVaYJjlAO9TJ7PlRaajsyT5hFxGTopvLFhhKx2eG', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ff501c08-fb35-4a54-9784-a8338da8f00c', 'TAP151', 'TAP151', 'https://search.google.com/local/writereview?placeid=ChIJax8qaz_dDzkRehw2M4xG5JY', '$2a$06$fBNy3r45KVr7YzVFjb9bgOvz9VjqUdU3zBfXhAFleJWDPB/mLshd6', 'active', '2f88bb76-f5d6-42cb-bc4e-0328ed6b694e', '2026-10-12 04:14:10.857465+00', '2026-10-12 12:14:08.84351+00'),
  ('ff8d3cbb-74fb-48dd-ab64-853a3d7ab622', 'SP127', 'SP127', null, '$2a$06$bv4krVjCPguFZx4UfaZud.uJ6Nl5BTlpe76LIATse046eK34.0QDC', 'active', '3a29dff7-dd62-4bd0-9451-688ee3c3e53e', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ffa49d45-d880-4246-9f42-aa05d0c66c5a', 'SP449', 'SP449', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('ffa72746-5f84-47d4-bc0a-dc0770e9331c', 'TFF128', 'TFF128', null, '$2a$06$7cldlqdu2lz87Why3mlO2.0bUQgbnd5n3ByezBQdoBJbRqP.f3iJm', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ffb4253d-53d4-42f6-a89e-8092b057d539', 'MTM245', 'MTM245', null, '$2a$06$fwVzB6K32UFHN3iAdK8JfeVvMwiiOsXNFjdQyNxEknAC8.P3IefYa', 'active', 'f86b039d-12ae-4858-90a0-ad6a8ecfcd06', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ffc3b6ab-2f8e-433f-bb0a-3da6d20efc64', 'TFF158', 'TFF158', null, '$2a$06$pwBZc9VHdl.nsDGAjKZWX.BQpKhl0Npq8AOCOFZPS8Jbal3s6Xu.S', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('ffca608d-f717-4045-b885-f65eba6c62b1', 'SP328', 'SP328', null, '$2a$06$80n46zp2yNwla8IjrCxIQu9BHMr5rP0SjjnKPxLMoSjOTk/.G0fu.', 'active', '709d74da-b1f9-48a6-ad43-d7de53794efb', '2026-10-13 10:37:29.758946+00', '2026-10-13 10:37:29.758946+00'),
  ('fffa3fdb-8de9-4c5d-a58e-b3663f8b4d64', 'T225', 'T225', null, '$2a$06$Oui43LTNqXu94yxVHmU1Y.VSSiVpTf/gQWUUcQnidpJLEuhkpVkkG', 'active', '4232b215-4e23-4ab2-b390-595c5863e44b', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00'),
  ('fffa9777-3f9f-4b04-a107-433c666e8fe4', 'TFF269', 'TFF269', null, '$2a$06$lfMD3QqmL.dDr1StxnBNneoPw/lQJ23I/5yOr6Ca1ndxVJ7a0Y2qu', 'active', '5a0634b5-2930-4b33-b36d-cf042a73d036', '2026-10-12 04:14:10.857465+00', '2026-10-12 04:24:36.069361+00')
ON CONFLICT (id) DO NOTHING;


-- ==============================================================================
-- RESTORING BACKUP DATA (PASSWORD ATTEMPTS LOG)
-- ==============================================================================
-- Step 4: Restore Historical Password Attempts (253 records)
INSERT INTO public.qr_password_attempts (id, qr_number, success, attempted_at) VALUES
  ('004f930d-4013-47e2-bafd-9cc612e09157', 'TAP210', true, '2026-10-12 12:12:44.708425+00'),
  ('01aef2c5-e6af-4632-aa1d-d72daf09027f', 'TAP305', false, '2026-10-13 05:35:12.989586+00'),
  ('01df6864-5e94-4a21-a33a-5dd721819ccd', 'TAP215', false, '2026-10-10 14:20:37.616954+00'),
  ('0226597d-4c8a-46b9-88ea-14fa46c76dfc', 'TFF032', true, '2026-10-12 17:51:33.517317+00'),
  ('03ac66df-a78c-4e86-8b14-8d7093204146', 'TAP389', false, '2026-10-13 06:35:14.246961+00'),
  ('05947c0e-2cab-472b-be76-6eafbe6f6dce', 'TP', false, '2026-09-29 14:49:46.277965+00'),
  ('0596d0c3-ca72-4f92-8d9a-befd10a77a81', 'TAP219', true, '2026-10-06 15:51:10.140738+00'),
  ('073a0c80-8ce4-4396-80a3-45c43f33aa01', 'TP2', true, '2026-09-29 14:51:00.195727+00'),
  ('07610806-56e7-412a-a83b-3f8d4d4fa920', 'TAP002', false, '2026-10-13 05:07:25.290261+00'),
  ('08f9d6fc-9b3d-4c9c-b0d8-31978ede688a', 'Z100', false, '2026-09-28 15:04:38.129256+00'),
  ('0ae40fac-00d4-41bf-81d1-4caa13066c9e', 'TAP232', true, '2026-10-12 13:39:47.706244+00'),
  ('0d5e0d53-fece-4d5d-9877-9115607139c8', 'SP120', true, '2026-10-10 08:03:13.097004+00'),
  ('0d7b2239-0931-448d-a847-1f43c8fbd5e9', 'TAP189', true, '2026-10-10 09:25:24.204698+00'),
  ('0dd65614-5003-4fde-8c26-7c5798dab298', 'TAP122', true, '2026-10-12 09:20:01.179139+00'),
  ('0dd6abcd-92f2-45b0-a649-599f5d38ee8c', 'TAP156', true, '2026-10-12 13:31:43.538188+00'),
  ('0e1bf7ad-e43a-41cd-87aa-2c09c29f9011', 'TAP322', false, '2026-10-13 10:41:35.010601+00'),
  ('0f15934d-df58-49af-a723-07bfcc0db48c', 'TAP217', true, '2026-10-06 16:05:52.771782+00'),
  ('0fa89f72-0d10-4116-bb81-66e1f4115c1f', 'TAP130', true, '2026-10-10 12:01:21.398739+00'),
  ('101f57b8-7dc1-48b6-8161-02d8694ee934', 'TAP309', true, '2026-10-13 09:37:49.849928+00'),
  ('111b87d1-0cf3-4f00-8373-473595014301', 'TAP161', true, '2026-10-07 09:04:03.757687+00'),
  ('113c475a-0100-4887-9f3c-3f64c54b609b', 'TAP169', true, '2026-10-12 13:47:45.17741+00'),
  ('11449158-d853-47e3-af86-d1e64e4e1808', 'TAP070', false, '2026-10-12 08:46:41.708955+00'),
  ('1173c6f9-0d45-4b43-be8c-d766a791fad5', 'TAP209', true, '2026-10-12 12:32:36.581724+00'),
  ('12cdf09a-4449-4440-b5bc-eee006ae7d70', 'TAP322', false, '2026-10-13 10:28:38.508668+00'),
  ('1494bff0-8637-4fec-9c0c-905d2f0b2640', 'TAP244', true, '2026-10-12 11:12:09.583307+00'),
  ('168ddb96-e715-43ed-88f3-7239c0b386ad', 'TAP205', true, '2026-10-07 11:06:24.419391+00'),
  ('17399b72-8d8b-4004-9cd9-b7c373544639', 'TAP163', true, '2026-10-12 17:15:19.284206+00'),
  ('173dacec-9776-4de7-80a6-b759e43d15b1', 'TAP210', true, '2026-10-08 11:40:11.546767+00'),
  ('184b456b-3966-4c79-a33e-5433486ccb2f', 'TAP389', false, '2026-10-13 06:35:12.467895+00'),
  ('198ec57b-185a-4b6b-b1de-0f63a4359ea3', 'TAP202', true, '2026-10-08 15:06:02.140414+00'),
  ('19bbbd96-c10e-451f-9bee-18c687b16b4e', 'SP039', true, '2026-10-13 12:29:31.715443+00'),
  ('19e0f2bf-2432-4a5f-9d92-42d5be2a2248', 'TP', false, '2026-09-29 14:49:42.235073+00'),
  ('1b420f43-ddf8-4557-a342-32c61bd5641f', 'SP006', false, '2026-10-13 06:21:54.476604+00'),
  ('1b889e7f-ddb3-411a-ad69-da94746c029c', 'TAP083', true, '2026-10-03 20:45:50.795553+00'),
  ('1c4ff9f8-2c8f-4682-9401-a2a007117842', 'TAP231', true, '2026-10-12 11:08:42.508191+00'),
  ('1df1f316-e2af-40e2-aab8-31ae032320c0', 'TAP151', true, '2026-10-08 11:28:19.177549+00'),
  ('201d3575-9f12-4aee-8a12-60f371ac64ae', 'TAP305', false, '2026-10-13 05:35:04.388299+00'),
  ('20908efc-dd4e-4ba6-b21f-47709cd7377f', 'TAP156', true, '2026-10-07 14:34:19.976793+00'),
  ('21256923-64d4-48a3-bef4-0f867c3aebcb', 'TAP152', true, '2026-10-12 11:05:39.569745+00'),
  ('213dffa5-6e43-4c4d-a4ca-f1ba4457da05', 'TAP241', true, '2026-10-08 12:32:56.553499+00'),
  ('2376bfb0-f536-4647-b3f5-907859c37e07', 'TAP036', false, '2026-10-12 05:30:00.504264+00'),
  ('245f142f-793a-42ac-aa69-523e93f190e2', 'TAP400', false, '2026-10-13 11:40:30.539207+00'),
  ('247c6eec-a46c-4042-8e0b-4fbcdf0cc064', 'TAP200', true, '2026-10-10 13:12:56.186956+00'),
  ('249be323-a04a-41dd-af57-23fb60687925', 'TAP127', true, '2026-10-10 12:11:32.268046+00'),
  ('24c84937-bdfe-418d-b893-ff49174a573c', 'TAP216', true, '2026-10-12 11:06:37.26335+00'),
  ('27ae2970-1170-4a04-a359-491b180cff4f', 'SP221', false, '2026-10-11 06:32:05.445657+00'),
  ('28b36019-7f9a-4bf6-90b6-11999cabe054', 'TAP194', true, '2026-10-08 12:38:25.720205+00'),
  ('28e2c775-387f-4e5d-b1ba-b89ff3439f0d', 'TAP305', false, '2026-10-13 05:35:06.860137+00'),
  ('29287874-9887-47fe-a04f-c907988246c2', 'TAP002', false, '2026-10-13 05:07:47.303816+00'),
  ('2969423d-c848-48f0-9eb4-2eabb7570a5b', 'TAP174', true, '2026-10-08 13:34:59.839156+00'),
  ('2a29f6f5-ab2e-47c4-a2ba-8c621fc9b902', 'TAP173', true, '2026-10-07 12:30:51.056289+00'),
  ('2c24aaf3-ad48-4dbb-8796-f7e279ab8ef4', 'TAP206', true, '2026-10-06 13:00:21.816713+00'),
  ('2c77588b-3192-4cf3-bb5d-43ccea3decad', 'TAP160', true, '2026-10-12 13:07:59.058445+00'),
  ('2ebce90c-0bb2-4932-ab5f-d626706c7c1d', 'TAP235', false, '2026-10-10 08:24:00.472684+00'),
  ('30bf09c7-6a0c-4d42-bc92-390a273b5f6f', 'TAP137', true, '2026-10-12 08:51:46.996707+00'),
  ('327868a9-a8bf-41a7-b39e-d8978ab065a5', 'TAP195', true, '2026-10-06 13:25:21.971392+00'),
  ('328f20c0-a1c4-43f2-9836-f1abac00af9f', 'TAP168', true, '2026-10-12 11:21:37.306016+00'),
  ('33386e4b-55df-4300-8a25-51c7bf64eb11', 'TAP210', false, '2026-10-12 07:06:35.733599+00'),
  ('3428bbc0-76fb-45f3-9adb-42ca3075987a', 'TAP002', false, '2026-10-13 05:07:49.11884+00'),
  ('34dda9c3-f7ec-4fa5-bfa3-9a02ebb9d6f0', 'TAP333', false, '2026-10-13 15:04:14.553326+00'),
  ('361f103f-89a5-4afb-b491-1d2fc03353ea', 'SP277', true, '2026-10-11 08:08:31.282068+00'),
  ('3680fb78-7036-4210-8710-4ebad976631d', 'TAP383', false, '2026-10-13 10:43:45.664882+00'),
  ('36a85e6f-6182-4d3b-a1b5-321cf0a5a537', 'TAP002', true, '2026-10-03 20:53:42.195751+00'),
  ('37522945-e279-43c7-bc02-08665296dc07', 'SP010', true, '2026-10-11 07:15:11.113499+00'),
  ('37861c84-19ee-44d6-ab44-e90a5c83302b', 'TAP171', true, '2026-10-12 12:45:03.258691+00'),
  ('388740dc-599f-4d6f-96c5-32fbbdb078f1', 'TAP158', true, '2026-10-07 11:57:11.358871+00'),
  ('3aa62412-55a4-4c0c-85e3-26bfb1660581', 'TAP188', true, '2026-10-13 09:31:44.537711+00'),
  ('3cc70bf3-b786-4731-9502-df846b688aa2', 'TAP157', true, '2026-10-12 11:14:34.985864+00'),
  ('3d3901e3-be0d-446c-b2f2-d9ff5cac4bd6', 'HAHA1', true, '2026-09-28 17:13:50.519281+00'),
  ('3d4179f9-23c5-4710-a86d-eba1396eb0fd', 'TAP095', false, '2026-10-12 12:47:50.130917+00'),
  ('3eb2aed4-ff30-4b37-833b-e8dd9f03374f', 'TAP372', true, '2026-10-13 06:44:31.319143+00'),
  ('3ff939e7-3e7f-4f93-87ab-2720132a74c0', 'TAP242', true, '2026-10-08 12:31:02.680009+00'),
  ('40cf5fe3-e4f3-4039-a2ae-6f7c1ee6ad1a', 'TAP219', true, '2026-10-12 13:54:47.050569+00'),
  ('4127e9a9-0ddb-481c-9f5c-58a8a9928697', 'SP006', true, '2026-10-13 07:01:01.71828+00'),
  ('4149bd42-160e-4430-9b12-96b42b10cf25', 'SP006', false, '2026-10-13 06:34:52.992777+00'),
  ('41c0b664-1913-44dc-8131-2363b75761cf', 'TAP227', true, '2026-10-08 14:29:06.370184+00'),
  ('4289c223-7a2b-4d83-849a-45ddd177d728', 'TAP154', true, '2026-10-08 15:33:27.866664+00'),
  ('42a633fe-e278-4b16-bd3e-43b85a62f153', 'TAP322', false, '2026-10-13 10:42:08.343813+00'),
  ('438527db-b485-4e42-ba16-b820e9b8e808', 'SP097', false, '2026-10-12 07:08:19.901224+00'),
  ('43a26cd9-5108-4047-8496-47dcb2469613', 'TAP046', true, '2026-10-10 11:25:02.008844+00'),
  ('43f429f9-1054-4ef1-8ca7-aa198693c094', 'TFF012', false, '2026-10-12 17:50:37.805799+00'),
  ('44a19418-4d34-4dc8-976a-e1c69a5213a8', 'TAP229', true, '2026-10-07 15:40:30.184885+00'),
  ('46cbd662-2f27-4843-bab0-277092625b68', 'NEW1', true, '2026-09-28 17:03:02.399171+00'),
  ('46e61374-d661-454a-85d2-88d0f0bd654d', 'TAP181', true, '2026-10-12 14:05:38.78184+00'),
  ('48734160-243d-4871-b6df-253823e170ea', 'TAP036', true, '2026-10-12 05:32:29.129163+00'),
  ('4a6d53f4-8a6a-4a62-92d5-1ee33b67ccba', 'TAP134', true, '2026-10-10 09:02:22.535466+00'),
  ('4c0203c0-f5dd-4fff-ac22-3aa84ec7c363', 'TAP003', false, '2026-10-12 10:26:36.835959+00'),
  ('4cf7ff49-f118-48ec-9fc3-c9d51faba147', 'TAP243', true, '2026-10-08 11:36:31.394191+00'),
  ('4f65d2b1-99d1-4035-8df7-91d7deb3d849', 'TAP305', false, '2026-10-13 05:35:06.038837+00'),
  ('4f953628-dfed-46e1-8c5f-5ed524bb9550', 'TAP305', true, '2026-10-08 12:29:17.973658+00'),
  ('504d634d-2577-464c-9060-fa1de9b78683', 'TAP389', false, '2026-10-13 06:35:10.649689+00'),
  ('53305a1f-7bc7-47ac-910f-65630e23af3d', 'TAP036', false, '2026-10-12 05:30:43.571362+00'),
  ('5484650f-4202-4331-b8f7-a7931b253227', 'TAP226', false, '2026-10-12 11:04:01.212712+00'),
  ('58234ad7-80d7-4098-98e9-bbda5b59e61a', 'TAP241', true, '2026-10-12 12:20:03.955612+00'),
  ('58ddf7cc-6ca1-4628-a373-6973b433afcf', 'SP221', true, '2026-10-11 06:43:02.742797+00'),
  ('5cc19c53-a4e7-4ac4-a751-fe863a1a5535', 'Z100', false, '2026-09-28 15:05:03.234782+00'),
  ('5ccf98d9-137c-4c09-a493-db4fbaaf1e39', 'TAP095', false, '2026-10-12 12:48:06.310793+00'),
  ('5eead20f-12fa-4b3d-9ca2-6e9d7015c04a', 'TAP246', true, '2026-10-10 12:07:27.269104+00'),
  ('6002de07-3e20-4ccf-ab54-1b01db40a53b', 'SP008', false, '2026-10-07 07:46:50.058586+00'),
  ('602300da-97f8-4b86-9881-b107d6bce695', 'TAP216', false, '2026-10-12 11:05:44.654793+00'),
  ('6057fa4a-9827-47a8-bcf5-ef4e12e76186', 'TAP070', false, '2026-10-12 08:46:54.063132+00'),
  ('60628445-bf28-485e-9b6a-c12398c01c92', 'TAP127', true, '2026-10-13 17:29:41.813478+00'),
  ('63678296-1478-4d31-977f-ea1e2f79e789', 'TAP322', false, '2026-10-13 10:39:39.080742+00'),
  ('6434b068-b53d-474d-8b09-416aba374d1a', 'TAP245', true, '2026-10-12 12:51:48.915695+00'),
  ('64838238-f86e-4692-aa0d-ff204aacccc4', 'TAP200', true, '2026-10-12 12:28:05.569687+00'),
  ('64c20c0d-c012-483a-a4b7-89ac270e19f9', 'TAP242', true, '2026-10-12 12:20:23.144053+00'),
  ('65b1a59e-cfbb-40e9-a06a-346e21c9c2e8', 'TAP170', true, '2026-10-12 14:08:32.454423+00'),
  ('65cdff6c-46f0-4c3c-9b59-f11c6d85c540', 'TAP161', true, '2026-10-12 14:14:04.809439+00'),
  ('66415a03-631d-42db-a285-672aaa01f147', 'TAP003', true, '2026-10-12 10:27:01.18404+00'),
  ('6670fbd4-edf1-4765-a76b-9a70cee11d7f', 'TAP252', true, '2026-10-01 11:08:34.040315+00'),
  ('66e162a7-89f0-46f6-8504-90717f441872', 'TAP046', true, '2026-10-13 08:14:47.063514+00'),
  ('69da5226-eda9-4cf9-886a-1e9653f0d92a', 'HTTT444', false, '2026-09-28 17:23:23.189147+00'),
  ('6ae01adf-9823-434a-bbcf-7b0c05b23ee1', 'TAP137', true, '2026-10-11 08:39:02.339034+00'),
  ('6b022235-4ad4-48d4-90e5-5f2959599ab0', 'TAP394', true, '2026-10-06 10:35:45.730554+00'),
  ('6b37c290-f882-446c-a1ed-14e74436d773', 'TAP182', true, '2026-10-12 12:25:27.324617+00'),
  ('6b97fc8c-5091-4123-8f0c-cea9da6c218f', 'TAP046', false, '2026-10-13 08:14:35.025084+00'),
  ('6cefde53-78cd-414d-9c2a-ccbb4f9128cb', 'Z100', false, '2026-09-28 15:06:03.735144+00'),
  ('706d7b79-f13c-446c-aa25-bf371e3220c8', 'TAP196', true, '2026-10-08 14:31:59.610994+00'),
  ('7128f4f0-da79-4af2-9f42-eac1a914b0db', 'TAP209', true, '2026-10-08 13:00:37.553022+00'),
  ('74746245-6ae8-40a1-9233-b8258359a709', 'TAP186', true, '2026-10-12 13:27:21.855062+00'),
  ('7484b56d-ac5c-43f5-855d-7b9a78ec14bc', 'SP097', false, '2026-10-10 09:49:19.320588+00'),
  ('75403331-0e64-4eba-ad49-0a0e1fe69efc', 'TAP394', false, '2026-10-06 10:31:15.054445+00'),
  ('7692937f-9c17-4ac0-9918-87f0cc79830d', 'TAP070', true, '2026-10-12 08:48:50.238457+00'),
  ('76de7b20-0076-4412-896f-1014d9da0d8a', 'SP097', true, '2026-10-10 09:50:17.578307+00'),
  ('776a58c5-6061-4ae1-bc21-3a5915fe6f78', 'MTM122', true, '2026-09-28 17:25:55.632045+00'),
  ('779de716-e87f-4f1e-a5d5-a5fdf9317eaa', 'TAP159', true, '2026-10-12 14:17:44.710605+00'),
  ('7844ab64-532f-4731-a05c-1bf062e4a4f8', 'TAP372', true, '2026-10-07 09:49:38.700382+00'),
  ('78ca7f8f-846d-40cc-b171-e5b2f2419f99', 'TAP394', false, '2026-10-06 10:31:37.167484+00'),
  ('78d536ec-d686-4bb7-9730-77aee13c45e1', 'TAP002', false, '2026-10-13 05:07:26.315111+00'),
  ('7c76cc25-f557-40fd-81dd-aa0809ad37d5', 'HAHA1', true, '2026-09-28 17:13:35.430258+00'),
  ('7e6feb7f-9922-4444-8480-32bf3f7f8ac3', 'TAP305', false, '2026-10-13 05:35:07.496035+00'),
  ('7f6f0be9-87ae-4380-b089-e0d156b63125', 'TAP221', true, '2026-10-12 12:56:03.366276+00'),
  ('7fa928f1-b102-419a-8a7b-c5443c277a6c', 'TAP305', false, '2026-10-13 05:34:27.209706+00'),
  ('822947f2-680b-4584-9c3f-6dbab64a15f2', 'TAP160', true, '2026-10-10 13:25:01.214722+00'),
  ('83037858-e6db-4f0e-934e-a2a90a139821', 'SP006', false, '2026-10-13 06:22:12.080209+00'),
  ('83a4d640-2208-4fcc-9357-e9e16b3afa5f', 'TAP333', false, '2026-10-13 15:07:29.089919+00'),
  ('855ff73e-0d6f-498a-bb6f-3aebdf0468b2', 'SP006', false, '2026-10-13 06:21:25.639993+00'),
  ('862eaa3c-e433-4be5-b147-3fb1186fb2b2', 'TAP322', false, '2026-10-13 10:39:09.103555+00'),
  ('86314b14-0af3-40ab-acd4-84646de36f5b', 'TAP207', true, '2026-10-10 14:52:55.530127+00'),
  ('8690071c-6c85-4a17-834b-64b1e71e6b52', 'TAP070', true, '2026-10-11 08:42:21.163056+00'),
  ('881a873a-f98b-466c-ae92-93380928847a', 'TAP095', false, '2026-10-12 12:48:05.081533+00'),
  ('8aabc623-ea62-4bcd-ab68-01258f330b13', 'TAP036', false, '2026-10-12 05:30:44.871931+00'),
  ('8ace59d8-b98f-42ad-b1bf-5e590123acf2', 'TAP036', true, '2026-10-10 18:42:10.853939+00'),
  ('8b447009-de64-42cc-9499-32ef489d01ed', 'TAP378', false, '2026-10-13 14:57:50.119046+00'),
  ('8b920daa-1865-42c4-ac27-ba1c58435789', 'TAP164', true, '2026-10-12 11:12:07.853799+00'),
  ('8bb887f2-a0e9-4860-9e69-ed3e3cc60bb3', 'TAP221', true, '2026-10-10 11:49:40.620329+00'),
  ('8cf3f637-507b-4e3f-88ac-d78020bf619f', 'TFF012', false, '2026-10-12 17:50:39.904076+00'),
  ('8e5bda70-6256-4cec-ac3a-51f096d426d2', 'TAP396', true, '2026-10-11 10:48:19.466176+00'),
  ('91049215-faa0-46e9-9c17-51642c339cde', 'TAP041', true, '2026-10-01 10:47:28.859706+00'),
  ('93d1e0c0-4101-4a3d-952f-8df93e158314', 'TAP162', true, '2026-10-06 12:27:37.529998+00'),
  ('961ce2ad-d20c-418c-8a41-e4f12997dc37', 'TAP206', true, '2026-10-12 14:09:14.741802+00'),
  ('96443e15-5b57-4a5c-acb9-1e5c4057e4d1', 'TAP227', false, '2026-10-08 14:28:56.736002+00'),
  ('9a02f23a-b88c-4211-bf21-c28f850c9075', 'TAP189', true, '2026-10-12 11:33:56.179873+00'),
  ('9c7ca544-1a57-47d3-9c27-f318b4d1fe1d', 'TAP008', true, '2026-09-30 18:47:16.799757+00'),
  ('9d94354b-a2a7-4a71-b05a-08b0e1327896', 'TAP171', true, '2026-10-10 09:46:16.608923+00'),
  ('9e491f65-936c-44c8-a378-f148d01d019a', 'TAP134', true, '2026-10-12 11:38:08.847226+00'),
  ('9f4e4206-2220-4b27-9993-907ec58d02db', 'HTTT444', true, '2026-09-28 17:23:29.035785+00'),
  ('a01c006e-a723-40d0-a880-542d4c67fe0b', 'TAP193', true, '2026-10-12 11:56:01.449377+00'),
  ('a0eaa91a-60f2-484d-ba49-1b7e2ad4112e', 'TAP232', true, '2026-10-07 13:24:40.415221+00'),
  ('a373ffd4-6daa-4e3a-ac40-1f3740d9d99a', 'TAP154', true, '2026-10-12 12:34:10.063011+00'),
  ('a587995f-e842-41ed-9dd4-4b460a410928', 'TAP380', true, '2026-10-13 09:38:46.926399+00'),
  ('a68e0b49-aaff-47ba-ba4a-ac8793dd5c8c', 'TAP247', true, '2026-10-12 17:12:40.351614+00'),
  ('a6d8b920-db1d-42ae-bc03-a271e4c5a4b9', 'TAP215', true, '2026-10-10 17:18:29.153879+00'),
  ('a85dd66b-65a1-4cd1-8620-61823652469d', 'SP097', true, '2026-10-13 06:02:43.944334+00'),
  ('a8966951-39b4-4fc5-b497-0c1d336a20da', 'TAP389', false, '2026-10-13 06:35:13.588426+00'),
  ('a92a4fea-ac35-43e9-8755-5bd078302fe0', 'TAP381', true, '2026-10-03 08:06:50.305903+00'),
  ('a92e56be-9294-4372-8988-a0eadaef3bce', 'TF05', true, '2026-09-29 15:00:47.013902+00'),
  ('a9b8ba90-1f12-4f4a-9d27-817be9cbe7b3', '86', true, '2026-09-29 18:55:45.266741+00'),
  ('abb5f45a-02d1-44bd-862a-f4e30f1d4845', 'TAP173', true, '2026-10-13 14:50:00.797259+00'),
  ('ac9814b8-a10a-46ee-bf63-06acedfaabb2', 'TAP233', true, '2026-10-06 14:18:41.108566+00'),
  ('aceb97e1-acfb-4eae-9161-e117c8c8ff9d', 'TAP169', true, '2026-10-07 10:53:33.588167+00'),
  ('ae69df6e-2ca7-4d72-99c3-78b7412d505e', 'TAP322', false, '2026-10-13 13:09:35.894886+00'),
  ('b048030e-fc0c-45ae-8dab-e1a5ec4e18be', 'TAP235', true, '2026-10-12 12:06:20.209108+00'),
  ('b2005098-b58e-4763-a425-466d5f593e5d', 'TAP226', false, '2026-10-12 11:04:06.744875+00'),
  ('b207cf43-6ae1-4ee3-8ae8-e2cba83465d9', 'TAP389', false, '2026-10-13 06:35:13.321602+00'),
  ('b350325e-5148-44fe-a9e3-c3f021d713a0', 'TAP243', true, '2026-10-12 12:15:19.922333+00'),
  ('b3f3d6cb-b3d3-43ea-a2c7-2993b6dda246', 'TAP183', true, '2026-10-12 11:48:58.870013+00'),
  ('b56b6ffc-e043-4086-9579-af5dde71ea24', 'TAP394', false, '2026-10-06 10:31:38.24509+00'),
  ('b5a3abbc-11ff-45f4-8072-23747ea8cf08', 'TAP094', true, '2026-10-13 12:52:28.778646+00'),
  ('b61e6fb4-047e-47a4-9c6e-050752c0127f', 'TAP185', true, '2026-10-07 11:32:08.802833+00'),
  ('b73b7734-dec9-4160-b612-63478193ecd7', 'TAP106', true, '2026-10-13 13:05:46.403192+00'),
  ('b86ec00b-a13a-47bd-84e2-3ea00db04ea2', 'TAP048', true, '2026-10-12 11:13:39.267181+00'),
  ('bacfcb38-1dd8-4b7c-a6ab-64db6b0bc1c3', 'TAP210', false, '2026-10-12 07:06:29.20577+00'),
  ('bbad2363-ed04-4682-a2da-8f492400c179', 'TAP217', true, '2026-10-12 13:51:24.641704+00'),
  ('bd71b22a-b57e-4231-bebb-3a3e82ade616', 'TAP236', true, '2026-10-06 14:31:51.853872+00'),
  ('bd7c2a4a-be57-41bd-9229-89837bf5eb7f', 'TAP398', true, '2026-10-10 08:59:48.160292+00'),
  ('bdb5421d-c084-4e6d-a630-74f681824b97', 'TAP322', false, '2026-10-13 13:08:07.422895+00'),
  ('be1a8977-8ac1-4ac3-b69f-aa7dc5f8bede', 'TAP322', false, '2026-10-13 10:29:04.510012+00'),
  ('bf62b03f-16bb-492e-b85d-39d5df389965', 'TAP159', true, '2026-10-06 10:58:04.715092+00'),
  ('bfd50182-40e6-44b2-a632-39347637432c', 'TAP155', true, '2026-10-08 12:25:53.792883+00'),
  ('c0354616-a628-4ddc-8450-737ea709ff73', 'TAP181', true, '2026-10-06 13:23:09.591107+00'),
  ('c097ca2a-495e-4744-9487-65bc2046dd6d', 'TAP215', true, '2026-10-10 17:38:43.179809+00'),
  ('c0dd5b6e-a1e9-4407-a35b-663bfdf0edd7', 'TAP222', true, '2026-10-05 14:14:05.012436+00'),
  ('c35fa277-4ae3-482d-bfbd-6ee2e1670d1a', 'TAP220', true, '2026-10-10 10:18:26.772824+00'),
  ('c428f272-2145-4e51-bba5-4a6cb075e815', 'TAP123', true, '2026-10-11 08:50:04.256672+00'),
  ('c5acee84-9034-478e-9042-59159674fb3e', 'TAP215', false, '2026-10-10 14:20:54.633626+00'),
  ('c5bcb90d-f72d-4398-85ea-ac9bdad34b75', 'TESTFLOW1', true, '2026-09-28 17:40:34.930359+00'),
  ('c5d4e921-96e6-40c3-ba93-54d92da74ed5', 'TAP220', true, '2026-10-12 12:48:12.243859+00'),
  ('c620b939-6688-4a85-8add-d8bcd2ef1b6d', 'TAP194', true, '2026-10-12 12:21:18.055207+00'),
  ('c628ad8a-95e5-4de7-9f9d-e39d52601a3d', 'TAP185', true, '2026-10-12 13:43:57.205221+00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.qr_password_attempts (id, qr_number, success, attempted_at) VALUES
  ('c86ecec5-2fe3-4896-b1c3-d497b305d037', 'SP221', false, '2026-10-11 06:42:05.94323+00'),
  ('c8f01be8-9144-46e1-a6b6-67d7a25f05b4', 'TAP070', false, '2026-10-12 08:46:52.981736+00'),
  ('c94364b4-0c77-4a15-b962-1d54bcc201a0', 'TAP215', true, '2026-10-10 14:22:53.833678+00'),
  ('c944c4ed-5c6a-447a-9be3-415d2a686e8f', 'TAP309', true, '2026-10-10 11:00:56.180299+00'),
  ('ca02c076-ef17-43d8-88f2-6d2d63b8f825', 'TAP333', false, '2026-10-13 15:05:01.310769+00'),
  ('ca8fde3b-e5d7-4a62-8022-e04d66692152', 'SP097', false, '2026-10-12 07:08:30.598107+00'),
  ('cc9d5744-7ecf-48a8-9679-8692b4f785ec', 'TAP380', true, '2026-10-10 11:12:15.402163+00'),
  ('cdf45810-d413-474f-b4e4-1c373aa68c44', 'TAP245', true, '2026-10-10 10:44:00.17142+00'),
  ('d15fa820-c0cf-44de-99e4-5393ca15a590', 'TAP235', true, '2026-10-10 08:24:33.517747+00'),
  ('d1676766-60d5-4fcf-840e-73637acb352e', 'TAP130', false, '2026-10-10 11:59:42.499139+00'),
  ('d207dcbd-5aff-493f-9524-df3c61b3f86e', 'TAP215', false, '2026-10-10 14:20:53.374047+00'),
  ('d218ae78-8e61-4793-971d-2d338340653e', 'TAP389', false, '2026-10-13 06:35:14.997874+00'),
  ('d441a1c8-2025-4669-b35d-b54369f2367b', 'TAP205', true, '2026-10-12 13:45:36.742454+00'),
  ('d4534077-35f0-4aea-b093-faa93183e1cf', 'TAP151', true, '2026-10-12 12:14:08.84351+00'),
  ('d4d9fa49-f73a-4c0c-9e97-dab8e21c0517', 'Z100', true, '2026-09-28 17:18:54.828425+00'),
  ('d4e37b1b-8186-4001-a93e-a07f56e32c17', 'TAP010', true, '2026-10-12 06:52:44.576147+00'),
  ('d71a2a9f-f6c7-48c1-a98b-28a8fc1fdfbc', 'TAP186', true, '2026-10-07 14:24:45.43072+00'),
  ('d770f3ab-0737-4cba-be60-900a838d8681', 'TAP095', false, '2026-10-12 12:48:07.304732+00'),
  ('d805603f-3064-4f01-afe2-6345a1e1be14', 'SP103', true, '2026-10-12 12:41:43.843491+00'),
  ('dd93e9dd-412e-48ec-84e6-ee130dc5f26e', 'TAP395', true, '2026-10-10 11:44:25.190097+00'),
  ('e1314065-4b59-45e4-9cd8-03431a5c3d94', 'TAP226', false, '2026-10-12 11:04:04.459204+00'),
  ('e146fa13-eeaa-482f-bb8e-02998f6249b0', 'TAP002', false, '2026-10-13 05:07:16.542771+00'),
  ('e24bf943-04e2-410c-ad95-1d025c32d4d2', 'TAP123', true, '2026-10-12 12:20:32.654282+00'),
  ('e2b59289-b4f9-4d95-ba67-4f13b57757f1', 'TAP153', true, '2026-10-12 11:00:58.635717+00'),
  ('e38dd152-b1ff-42c6-9b61-bb05ee0a1388', 'TAP229', true, '2026-10-12 12:39:58.173621+00'),
  ('e456bc61-2a3e-47f4-b1db-a39729bf753a', 'Z100', true, '2026-09-28 15:06:13.402401+00'),
  ('e6a67a4b-ee40-4185-998c-4599425922b6', 'TAP152', true, '2026-10-05 14:12:33.006098+00'),
  ('e717dc4c-0637-48e5-a20b-19be90ec3645', 'TAP155', true, '2026-10-12 12:29:15.388065+00'),
  ('e804608a-a315-491d-9850-57b20e573fba', 'TAP094', false, '2026-10-13 12:52:20.459737+00'),
  ('e94f221f-6626-446d-a2e2-1d2fbaff9d1f', 'TAP233', true, '2026-10-12 13:59:00.464218+00'),
  ('ea49b51a-d51f-4f56-8ed7-e176f320460b', 'TAP002', false, '2026-10-13 05:07:26.181905+00'),
  ('eb22acd6-da15-4f84-b527-667602d30b5d', 'TAP036', false, '2026-10-12 05:28:53.159383+00'),
  ('eb93d624-4f56-4180-9814-04c2be8f1257', 'TAP369', true, '2026-10-07 12:49:13.82745+00'),
  ('ec7d3673-8f5a-4eac-ae4c-2e08e1325597', 'TAP246', true, '2026-10-12 12:54:24.19032+00'),
  ('eca0e73f-0498-4b08-8706-0a0f46a08e2a', 'TAP123', false, '2026-10-11 08:49:28.884936+00'),
  ('ee00c504-0cde-40c2-94f3-922b8678c015', 'TAP333', false, '2026-10-13 15:04:04.150693+00'),
  ('ef6d50d0-d076-4dfc-bd24-e48ee0e73f02', 'TAP394', false, '2026-10-06 10:31:07.30177+00'),
  ('ef8a835e-0ecb-4472-a8b7-f3fba11c2df5', 'SP008', true, '2026-10-07 07:47:14.011502+00'),
  ('efd7643f-d948-4b63-b2f9-974fc7d5a3ee', 'TAP226', false, '2026-10-12 11:03:39.721335+00'),
  ('f1a7a6fa-c1a2-4ac4-a0c4-9f2f3532d9f4', 'TAP170', true, '2026-10-06 12:57:35.086853+00'),
  ('f267c12d-65f0-4ba1-ba02-ed313f1c589c', 'TAP226', false, '2026-10-12 11:04:05.620869+00'),
  ('f27e2e5c-86e0-48b0-ba6d-44c73370edd6', 'TAP095', true, '2026-10-12 13:27:24.769623+00'),
  ('f38ccac2-358c-4885-b07c-7bffe32de12b', 'TAP320', false, '2026-10-13 14:50:25.180646+00'),
  ('f486cf93-8d8b-4366-b6fd-c8afa4dd4225', 'TAP132', true, '2026-10-13 13:11:01.061014+00'),
  ('f5068b22-e06f-44ad-9481-fa7ab83287a1', 'TAP345', true, '2026-10-10 11:06:11.579828+00'),
  ('f51bab91-fcf1-4339-a64e-3c5f704e7e88', 'TAP207', true, '2026-10-12 13:12:22.687799+00'),
  ('f54212cd-f8fa-4624-9998-69252f5e18e0', 'TAP389', true, '2026-10-13 08:28:33.368601+00'),
  ('f61f0861-7b92-4aee-ab0b-be251f829cb7', 'TAP183', true, '2026-10-08 11:26:10.458024+00'),
  ('f7f0e19e-5cde-4953-9db1-7f027ee8ae75', 'TAP182', true, '2026-10-08 12:29:26.404781+00'),
  ('f82d737e-ca90-42f8-aee3-1195ce59cce9', 'TAP322', false, '2026-10-13 13:09:14.628265+00'),
  ('f985e997-85fa-4eca-9a37-9e87de5182c4', 'TAP226', false, '2026-10-12 11:04:33.274108+00'),
  ('fa1876a4-56bb-40fd-8aa1-406af070f588', 'TAP162', true, '2026-10-12 14:10:20.334451+00'),
  ('fb9bb685-653a-453f-9cac-e33d014e1a34', 'TAP305', false, '2026-10-08 12:06:47.353622+00')
ON CONFLICT (id) DO NOTHING;



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
