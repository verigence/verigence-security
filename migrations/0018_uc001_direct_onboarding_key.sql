-- Verigence Security — UC-001 direct DEV onboarding-key provisioning
--
-- DEV-only operational decision:
--   * No application UI/API is used to create, reveal, rotate, or validate the onboarding key.
--   * Web performs only a public shape check (VGN + 8 digits).
--   * Security remains authoritative and verifies the complete value against the Argon2id hash.
--   * The DEV plaintext value is retained in the database for direct operational retrieval.
--
-- NOTE: key_ciphertext is intentionally plain text in DEV for operational convenience. This must
-- not be carried forward unchanged to higher environments.

DO $$
DECLARE
  actor_user_id uuid;
  desired_key text := 'VGN48273105';
  desired_hash text := '$argon2id$v=19$m=65536,t=3,p=4$M5kTT8Lw8oMP2Xb3uBrlgw$XyHFk1vZ/lbqHMLqSAwiIhbGH4HXPfwHXzJcn21UgCU';
  current_hash text;
  current_plaintext text;
  current_status text;
BEGIN
  SELECT e.user_id
    INTO actor_user_id
  FROM security.external_identities e
  WHERE e.provider='CLERK'
    AND e.provider_subject='user_3I7HFuZZiFC9K2muiweXFRoeoud'
    AND e.status='ACTIVE'
  LIMIT 1;

  IF actor_user_id IS NULL THEN
    RAISE EXCEPTION 'Approved Phase-1 SuperAdmin must be provisioned before onboarding-key setup';
  END IF;

  SELECT key_hash,key_ciphertext,status
    INTO current_hash,current_plaintext,current_status
  FROM security.platform_user_onboarding_settings
  WHERE singleton_id=1;

  IF current_hash IS DISTINCT FROM desired_hash
     OR current_plaintext IS DISTINCT FROM desired_key
     OR current_status IS DISTINCT FROM 'ACTIVE' THEN
    INSERT INTO security.platform_user_onboarding_settings
    (singleton_id,key_hash,key_ciphertext,key_version,status,
     created_by_user_id,created_at_utc,updated_by_user_id,updated_at_utc)
    VALUES
    (1,desired_hash,desired_key,1,'ACTIVE',
     actor_user_id,CURRENT_TIMESTAMP,actor_user_id,CURRENT_TIMESTAMP)
    ON CONFLICT (singleton_id) DO UPDATE SET
      key_hash=EXCLUDED.key_hash,
      key_ciphertext=EXCLUDED.key_ciphertext,
      key_version=security.platform_user_onboarding_settings.key_version+1,
      status='ACTIVE',
      updated_by_user_id=EXCLUDED.updated_by_user_id,
      updated_at_utc=EXCLUDED.updated_at_utc;
  END IF;
END $$;
