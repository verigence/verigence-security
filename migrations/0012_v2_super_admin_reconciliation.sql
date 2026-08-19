-- Verigence Security v2 — canonical Phase-1 SuperAdmin reconciliation
-- Bridges the approved Clerk SuperAdmin identity into both the retained legacy
-- platform role and the canonical v2 admin-role assignment. This migration is
-- intentionally narrow and does not migrate any other USER/role data.

BEGIN;

DO $$
DECLARE
  approved_subject constant text := 'user_3I7HFuZZiFC9K2muiweXFRoeoud';
  approved_user_id uuid;
  identity_status text;
  user_status text;
  principal_status text;
BEGIN
  SELECT ei.user_id, ei.status
    INTO approved_user_id, identity_status
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=approved_subject
  LIMIT 1;

  -- Never silently accept a different active SuperAdmin under either model.
  IF EXISTS (
    SELECT 1
    FROM security.platform_user_role_assignments pura
    WHERE pura.role_key='platform.super_admin'
      AND pura.status='ACTIVE'
      AND (approved_user_id IS NULL OR pura.user_id<>approved_user_id)
  ) THEN
    RAISE EXCEPTION 'Conflicting legacy SuperAdmin exists; approved Clerk identity is %', approved_subject;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM security.user_admin_role_assignments uara
    WHERE uara.role_key='SuperAdmin'
      AND uara.status='ACTIVE'
      AND (approved_user_id IS NULL OR uara.user_id<>approved_user_id)
  ) THEN
    RAISE EXCEPTION 'Conflicting v2 SuperAdmin exists; approved Clerk identity is %', approved_subject;
  END IF;

  -- Fresh environments may not have provisioned the Clerk USER yet. The
  -- operator-controlled provisioning service will create it later.
  IF approved_user_id IS NULL THEN
    RETURN;
  END IF;

  IF identity_status<>'ACTIVE' THEN
    RAISE EXCEPTION 'Approved SuperAdmin Clerk identity is not ACTIVE';
  END IF;

  SELECT u.status, sp.status
    INTO user_status, principal_status
  FROM security.users u
  JOIN security.security_principals sp ON sp.principal_id=u.user_id
  WHERE u.user_id=approved_user_id;

  IF user_status IS NULL THEN
    RAISE EXCEPTION 'Approved SuperAdmin Clerk identity is not linked to a Security USER';
  END IF;
  IF user_status<>'ACTIVE' OR principal_status<>'ACTIVE' THEN
    RAISE EXCEPTION 'Approved SuperAdmin USER/principal must be ACTIVE';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM security.user_tenant_operating_roles utor
    WHERE utor.user_id=approved_user_id AND utor.status='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'Approved SuperAdmin USER has an ACTIVE operating role';
  END IF;

  INSERT INTO security.platform_user_role_assignments
  (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
  SELECT
    md5('security-0012-legacy-superadmin-' || approved_user_id::text)::uuid,
    approved_user_id,
    'platform.super_admin',
    'ACTIVE',
    'BOOTSTRAP',
    CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1
    FROM security.platform_user_role_assignments
    WHERE user_id=approved_user_id
      AND role_key='platform.super_admin'
      AND status='ACTIVE'
  );

  INSERT INTO security.user_admin_role_assignments
  (assignment_id,user_id,role_key,scope_type,scope_id,status,
   assigned_by_user_id,assigned_at_utc)
  SELECT
    md5('security-0012-v2-superadmin-' || approved_user_id::text)::uuid,
    approved_user_id,
    'SuperAdmin',
    'PLATFORM',
    NULL,
    'ACTIVE',
    NULL,
    CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1
    FROM security.user_admin_role_assignments
    WHERE user_id=approved_user_id
      AND role_key='SuperAdmin'
      AND status='ACTIVE'
  );

  INSERT INTO security.admin_change_records
  (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
   operation_key,resource_type,resource_id,outcome,before_state_json,
   after_state_json,occurred_at_utc)
  VALUES (
    md5('security-0012-audit-superadmin-' || approved_user_id::text)::uuid,
    'migration-0012-v2-superadmin',
    'PLATFORM',
    NULL,
    approved_user_id,
    'platform.super_admin.v2_reconcile',
    'platform_user',
    approved_user_id::text,
    'SUCCESS',
    NULL,
    jsonb_build_object(
      'identityProvider','CLERK',
      'providerSubject',approved_subject,
      'legacyPlatformRole','platform.super_admin',
      'v2AdminRole','SuperAdmin',
      'scopeType','PLATFORM'
    ),
    CURRENT_TIMESTAMP
  )
  ON CONFLICT (admin_change_id) DO NOTHING;
END $$;

COMMIT;
