-- Verigence Security DEV — correct canonical Clerk subject for Phase-1 SuperAdmin.
--
-- Clerk user IDs are immutable for a Clerk user record. This migration corrects Security's
-- DEV binding to the actual existing SuperAdmin Clerk user:
--   user_3I7FdD5Pkmydsp23OfjH9hBMxpN
--
-- It does not authenticate by email and does not change the Web login contract.
-- It only reconciles Security-owned identity/admin state.

BEGIN;

DO $$
DECLARE
  canonical_subject constant text := 'user_3I7FdD5Pkmydsp23OfjH9hBMxpN';
  previous_subject constant text := 'user_3I7HFuZZiFC9K2muiweXFRoeoud';
  canonical_user_id uuid;
  previous_user_id uuid;
BEGIN
  SELECT ei.user_id
    INTO canonical_user_id
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=canonical_subject
  LIMIT 1;

  SELECT ei.user_id
    INTO previous_user_id
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=previous_subject
  LIMIT 1;

  -- Common DEV correction: Security already has the intended SuperAdmin USER but it is bound
  -- to the wrong Clerk subject. Preserve the Security USER and move only the immutable
  -- external-identity subject to the actual Clerk user ID.
  IF canonical_user_id IS NULL AND previous_user_id IS NOT NULL THEN
    UPDATE security.external_identities
       SET provider_subject=canonical_subject,
           status='ACTIVE'
     WHERE provider='CLERK'
       AND provider_subject=previous_subject;
    canonical_user_id := previous_user_id;
    previous_user_id := NULL;
  END IF;

  IF canonical_user_id IS NULL THEN
    RAISE EXCEPTION 'Actual DEV SuperAdmin Clerk subject % is not bound to any Security USER, and no prior SuperAdmin binding exists to reconcile', canonical_subject;
  END IF;

  -- The canonical SuperAdmin human must be active end-to-end for login.
  UPDATE security.external_identities
     SET status='ACTIVE'
   WHERE provider='CLERK'
     AND provider_subject=canonical_subject
     AND user_id=canonical_user_id;

  UPDATE security.users
     SET status='ACTIVE'
   WHERE user_id=canonical_user_id;

  UPDATE security.security_principals
     SET status='ACTIVE'
   WHERE principal_id=canonical_user_id
     AND actor_type='USER';

  -- Remove SuperAdmin classification from the previously assumed Clerk identity if it resolves
  -- to a different Security USER. Preserve that USER and its non-SuperAdmin data.
  IF previous_user_id IS NOT NULL AND previous_user_id <> canonical_user_id THEN
    DELETE FROM security.user_admin_role_assignments
     WHERE user_id=previous_user_id
       AND role_key='SuperAdmin';

    DELETE FROM security.platform_user_role_assignments
     WHERE user_id=previous_user_id
       AND role_key='platform.super_admin';
  END IF;

  -- Canonical v2 admin assignment used by active Security authorization.
  INSERT INTO security.user_admin_role_assignments
    (assignment_id,user_id,role_key,scope_type,scope_id,status,
     assigned_by_user_id,assigned_at_utc)
  SELECT
    md5('security-0019-v2-superadmin-' || canonical_user_id::text)::uuid,
    canonical_user_id,
    'SuperAdmin',
    'PLATFORM',
    NULL,
    'ACTIVE',
    NULL,
    CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1
    FROM security.user_admin_role_assignments
    WHERE user_id=canonical_user_id
      AND role_key='SuperAdmin'
      AND scope_type='PLATFORM'
      AND scope_id IS NULL
      AND status='ACTIVE'
  );

  -- Temporary legacy compatibility assignment retained by current DEV operational workflows.
  INSERT INTO security.platform_user_role_assignments
    (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
  SELECT
    md5('security-0019-legacy-superadmin-' || canonical_user_id::text)::uuid,
    canonical_user_id,
    'platform.super_admin',
    'ACTIVE',
    'BOOTSTRAP',
    CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1
    FROM security.platform_user_role_assignments
    WHERE user_id=canonical_user_id
      AND role_key='platform.super_admin'
      AND status='ACTIVE'
  );

  -- Fail closed if the correction did not produce the exact active chain used by login.
  IF NOT EXISTS (
    SELECT 1
    FROM security.external_identities ei
    JOIN security.users u ON u.user_id=ei.user_id
    JOIN security.security_principals sp ON sp.principal_id=u.user_id
    JOIN security.user_admin_role_assignments a ON a.user_id=u.user_id
    WHERE ei.provider='CLERK'
      AND ei.provider_subject=canonical_subject
      AND ei.status='ACTIVE'
      AND u.status='ACTIVE'
      AND sp.actor_type='USER'
      AND sp.status='ACTIVE'
      AND a.role_key='SuperAdmin'
      AND a.scope_type='PLATFORM'
      AND a.scope_id IS NULL
      AND a.status='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'DEV SuperAdmin reconciliation failed for Clerk subject %', canonical_subject;
  END IF;
END $$;

COMMIT;
