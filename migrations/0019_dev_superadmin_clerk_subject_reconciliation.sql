-- Verigence Security DEV — force the canonical Clerk subject for the Phase-1 SuperAdmin.
--
-- This is a Security-database reconciliation only. It does not call Clerk and it does not
-- authenticate by email. The canonical immutable Clerk user ID is:
--   user_3I7FdD5Pkmydsp23OfjH9hBMxpN
--
-- Reconciliation rules:
-- 1. If that Clerk subject is already mapped in Security, that Security USER is authoritative.
-- 2. Otherwise, move the existing DEV platform SuperAdmin's Clerk identity to that subject.
-- 3. Keep exactly one active Platform SuperAdmin classification and make the full human chain ACTIVE.

BEGIN;

DO $$
DECLARE
  canonical_subject constant text := 'user_3I7FdD5Pkmydsp23OfjH9hBMxpN';
  canonical_user_id uuid;
  current_superadmin_user_id uuid;
  current_superadmin_count integer;
  current_clerk_identity_id uuid;
BEGIN
  -- Prefer an existing Security mapping for the exact immutable Clerk subject.
  SELECT ei.user_id
    INTO canonical_user_id
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=canonical_subject
  LIMIT 1;

  -- Resolve the currently classified DEV Platform SuperAdmin. There must not be ambiguity.
  SELECT count(DISTINCT a.user_id)
    INTO current_superadmin_count
  FROM security.user_admin_role_assignments a
  WHERE a.role_key='SuperAdmin'
    AND a.scope_type='PLATFORM'
    AND a.scope_id IS NULL
    AND a.status='ACTIVE';

  IF current_superadmin_count > 1 THEN
    RAISE EXCEPTION 'DEV has % active Platform SuperAdmin USERs; refusing ambiguous Clerk-subject reconciliation', current_superadmin_count;
  END IF;

  IF current_superadmin_count = 1 THEN
    SELECT a.user_id
      INTO current_superadmin_user_id
    FROM security.user_admin_role_assignments a
    WHERE a.role_key='SuperAdmin'
      AND a.scope_type='PLATFORM'
      AND a.scope_id IS NULL
      AND a.status='ACTIVE'
    LIMIT 1;
  END IF;

  -- If the canonical Clerk subject is not mapped yet, bind it directly to the existing
  -- Security SuperAdmin USER. This is the requested DB-only correction.
  IF canonical_user_id IS NULL THEN
    IF current_superadmin_user_id IS NULL THEN
      RAISE EXCEPTION 'No existing DEV Platform SuperAdmin USER is available for Clerk-subject reconciliation';
    END IF;

    SELECT ei.external_identity_id
      INTO current_clerk_identity_id
    FROM security.external_identities ei
    WHERE ei.provider='CLERK'
      AND ei.user_id=current_superadmin_user_id
    ORDER BY CASE WHEN ei.status='ACTIVE' THEN 0 ELSE 1 END, ei.linked_at_utc
    LIMIT 1;

    IF current_clerk_identity_id IS NULL THEN
      INSERT INTO security.external_identities
        (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
      VALUES
        (md5('security-0019-clerk-' || current_superadmin_user_id::text)::uuid,
         current_superadmin_user_id,'CLERK',canonical_subject,'ACTIVE',CURRENT_TIMESTAMP);
    ELSE
      UPDATE security.external_identities
         SET provider_subject=canonical_subject,
             status='ACTIVE'
       WHERE external_identity_id=current_clerk_identity_id;

      -- Any additional historical Clerk identities for the same Security USER must not remain active.
      UPDATE security.external_identities
         SET status='REVOKED'
       WHERE provider='CLERK'
         AND user_id=current_superadmin_user_id
         AND external_identity_id<>current_clerk_identity_id
         AND status='ACTIVE';
    END IF;

    canonical_user_id := current_superadmin_user_id;
  END IF;

  -- The canonical SuperAdmin human must be active end-to-end for login.
  UPDATE security.external_identities
     SET status='ACTIVE'
   WHERE provider='CLERK'
     AND provider_subject=canonical_subject
     AND user_id=canonical_user_id;

  UPDATE security.users
     SET status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE user_id=canonical_user_id;

  UPDATE security.security_principals
     SET status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE principal_id=canonical_user_id
     AND actor_type='USER';

  -- The canonical Clerk identity is the DEV SuperAdmin. Remove active SuperAdmin classification
  -- from any other Security USER to keep the bootstrap authority unambiguous.
  DELETE FROM security.user_admin_role_assignments
   WHERE user_id<>canonical_user_id
     AND role_key='SuperAdmin'
     AND scope_type='PLATFORM'
     AND scope_id IS NULL;

  DELETE FROM security.platform_user_role_assignments
   WHERE user_id<>canonical_user_id
     AND role_key='platform.super_admin';

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

  UPDATE security.user_admin_role_assignments
     SET status='ACTIVE'
   WHERE user_id=canonical_user_id
     AND role_key='SuperAdmin'
     AND scope_type='PLATFORM'
     AND scope_id IS NULL;

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

  UPDATE security.platform_user_role_assignments
     SET status='ACTIVE'
   WHERE user_id=canonical_user_id
     AND role_key='platform.super_admin';

  -- Fail closed unless the exact requested Clerk subject resolves through the active login chain.
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
    RAISE EXCEPTION 'DEV SuperAdmin DB reconciliation failed for Clerk subject %', canonical_subject;
  END IF;
END $$;

COMMIT;
