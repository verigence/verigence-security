-- Verigence Security DEV — canonical human identities for UC-001 login validation.
--
-- Database-only reconciliation requested for DEV. No Clerk API is called.
--
-- Canonical identities:
--   SuperAdmin: jbrconsulting.it@gmail.com -> user_3I7FdD5Pkmydsp23OfjH9hBMxpN
--   TestUser:   gigsinopensource@gmail.com -> user_3I7HFuZZiFC9K2muiweXFRoeoud

BEGIN;

DO $$
DECLARE
  super_subject constant text := 'user_3I7FdD5Pkmydsp23OfjH9hBMxpN';
  super_email constant text := 'jbrconsulting.it@gmail.com';
  test_subject constant text := 'user_3I7HFuZZiFC9K2muiweXFRoeoud';
  test_email constant text := 'gigsinopensource@gmail.com';
  super_user_id uuid;
  test_user_id uuid;
  candidate_count integer;
  identity_id uuid;
BEGIN
  SELECT ei.user_id
    INTO super_user_id
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=super_subject
  LIMIT 1;

  IF super_user_id IS NULL THEN
    SELECT count(DISTINCT a.user_id), min(a.user_id)
      INTO candidate_count, super_user_id
    FROM security.user_admin_role_assignments a
    WHERE a.role_key='SuperAdmin'
      AND a.scope_type='PLATFORM'
      AND a.scope_id IS NULL
      AND a.status='ACTIVE';

    IF candidate_count <> 1 OR super_user_id IS NULL THEN
      RAISE EXCEPTION 'Cannot resolve exactly one DEV SuperAdmin USER for canonical Clerk subject %', super_subject;
    END IF;

    SELECT ei.external_identity_id
      INTO identity_id
    FROM security.external_identities ei
    WHERE ei.provider='CLERK'
      AND ei.user_id=super_user_id
    ORDER BY CASE WHEN ei.status='ACTIVE' THEN 0 ELSE 1 END, ei.linked_at_utc
    LIMIT 1;

    IF identity_id IS NULL THEN
      INSERT INTO security.external_identities
        (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
      VALUES
        (md5('security-0021-super-' || super_user_id::text)::uuid,
         super_user_id,'CLERK',super_subject,'ACTIVE',CURRENT_TIMESTAMP);
    ELSE
      UPDATE security.external_identities
         SET provider_subject=super_subject,
             status='ACTIVE'
       WHERE external_identity_id=identity_id;
    END IF;
  END IF;

  SELECT ei.user_id
    INTO test_user_id
  FROM security.external_identities ei
  WHERE ei.provider='CLERK'
    AND ei.provider_subject=test_subject
  LIMIT 1;

  IF test_user_id IS NULL THEN
    SELECT pti.user_id
      INTO test_user_id
    FROM security.phase1_test_identity pti
    WHERE pti.singleton_id=1
      AND pti.status='ACTIVE'
    LIMIT 1;
  END IF;

  IF test_user_id IS NULL THEN
    SELECT u.user_id
      INTO test_user_id
    FROM security.users u
    WHERE lower(u.primary_email)=test_email
    LIMIT 1;
  END IF;

  IF test_user_id IS NULL THEN
    RAISE EXCEPTION 'Cannot safely resolve the DEV TestUser USER for canonical Clerk subject %', test_subject;
  END IF;

  IF test_user_id=super_user_id THEN
    RAISE EXCEPTION 'Canonical SuperAdmin and TestUser identities resolve to the same Security USER';
  END IF;

  -- If TestUser was resolved through the singleton/email rather than its Clerk subject, replace
  -- its current Clerk mapping directly in Security. No provider API call is required.
  IF NOT EXISTS (
    SELECT 1 FROM security.external_identities
    WHERE provider='CLERK'
      AND provider_subject=test_subject
      AND user_id=test_user_id
  ) THEN
    SELECT ei.external_identity_id
      INTO identity_id
    FROM security.external_identities ei
    WHERE ei.provider='CLERK'
      AND ei.user_id=test_user_id
    ORDER BY CASE WHEN ei.status='ACTIVE' THEN 0 ELSE 1 END, ei.linked_at_utc
    LIMIT 1;

    IF identity_id IS NULL THEN
      INSERT INTO security.external_identities
        (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
      VALUES
        (md5('security-0021-test-' || test_user_id::text)::uuid,
         test_user_id,'CLERK',test_subject,'ACTIVE',CURRENT_TIMESTAMP);
    ELSE
      UPDATE security.external_identities
         SET provider_subject=test_subject,
             status='ACTIVE'
       WHERE external_identity_id=identity_id;
    END IF;
  END IF;

  -- Keep the two canonical provider mappings active and retire any extra active Clerk mapping
  -- on those two Security USERs.
  UPDATE security.external_identities
     SET status=CASE WHEN provider_subject IN (super_subject,test_subject) THEN 'ACTIVE' ELSE 'REVOKED' END
   WHERE provider='CLERK'
     AND user_id IN (super_user_id,test_user_id);

  -- Fail before updating emails if another live USER already owns either canonical address.
  IF EXISTS (
    SELECT 1 FROM security.users
    WHERE user_id<>super_user_id
      AND lower(primary_email)=super_email
      AND status IN ('ACTIVE','SUSPENDED')
  ) THEN
    RAISE EXCEPTION 'Canonical SuperAdmin email % is owned by another ACTIVE/SUSPENDED USER', super_email;
  END IF;

  IF EXISTS (
    SELECT 1 FROM security.users
    WHERE user_id<>test_user_id
      AND lower(primary_email)=test_email
      AND status IN ('ACTIVE','SUSPENDED')
  ) THEN
    RAISE EXCEPTION 'Canonical TestUser email % is owned by another ACTIVE/SUSPENDED USER', test_email;
  END IF;

  UPDATE security.users
     SET primary_email=super_email,
         status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE user_id=super_user_id;

  UPDATE security.users
     SET primary_email=test_email,
         status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE user_id=test_user_id;

  UPDATE security.security_principals
     SET principal_name=super_email,
         status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE principal_id=super_user_id
     AND actor_type='USER';

  UPDATE security.security_principals
     SET principal_name=test_email,
         status='ACTIVE',
         updated_at_utc=CURRENT_TIMESTAMP
   WHERE principal_id=test_user_id
     AND actor_type='USER';

  UPDATE security.platform_user_onboarding_requests
     SET email=super_email
   WHERE user_id=super_user_id;

  UPDATE security.platform_user_onboarding_requests
     SET email=test_email
   WHERE user_id=test_user_id;

  -- SuperAdmin belongs only to the canonical SuperAdmin USER, never TestUser.
  DELETE FROM security.user_admin_role_assignments
   WHERE user_id=test_user_id
     AND role_key='SuperAdmin';

  DELETE FROM security.platform_user_role_assignments
   WHERE user_id=test_user_id
     AND role_key='platform.super_admin';

  INSERT INTO security.user_admin_role_assignments
    (assignment_id,user_id,role_key,scope_type,scope_id,status,
     assigned_by_user_id,assigned_at_utc)
  SELECT
    md5('security-0021-v2-superadmin-' || super_user_id::text)::uuid,
    super_user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1 FROM security.user_admin_role_assignments
    WHERE user_id=super_user_id
      AND role_key='SuperAdmin'
      AND scope_type='PLATFORM'
      AND scope_id IS NULL
      AND status='ACTIVE'
  );

  INSERT INTO security.platform_user_role_assignments
    (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
  SELECT
    md5('security-0021-legacy-superadmin-' || super_user_id::text)::uuid,
    super_user_id,'platform.super_admin','ACTIVE','BOOTSTRAP',CURRENT_TIMESTAMP
  WHERE NOT EXISTS (
    SELECT 1 FROM security.platform_user_role_assignments
    WHERE user_id=super_user_id
      AND role_key='platform.super_admin'
      AND status='ACTIVE'
  );

  IF NOT EXISTS (
    SELECT 1
    FROM security.external_identities e
    JOIN security.users u ON u.user_id=e.user_id
    JOIN security.security_principals p ON p.principal_id=u.user_id
    JOIN security.user_admin_role_assignments a ON a.user_id=u.user_id
    WHERE e.provider='CLERK'
      AND e.provider_subject=super_subject
      AND e.status='ACTIVE'
      AND lower(u.primary_email)=super_email
      AND u.status='ACTIVE'
      AND p.status='ACTIVE'
      AND a.role_key='SuperAdmin'
      AND a.scope_type='PLATFORM'
      AND a.scope_id IS NULL
      AND a.status='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'Canonical SuperAdmin reconciliation did not produce the required active chain';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM security.external_identities e
    JOIN security.users u ON u.user_id=e.user_id
    JOIN security.security_principals p ON p.principal_id=u.user_id
    WHERE e.provider='CLERK'
      AND e.provider_subject=test_subject
      AND e.status='ACTIVE'
      AND lower(u.primary_email)=test_email
      AND u.status='ACTIVE'
      AND p.status='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'Canonical TestUser reconciliation did not produce the required active chain';
  END IF;
END $$;

COMMIT;
