\set ON_ERROR_STOP on
SELECT
  ei.provider_subject,
  ei.status AS identity_status,
  u.user_id,
  u.status AS user_status,
  sp.status AS principal_status,
  a.role_key,
  a.scope_type,
  a.scope_id,
  a.status AS assignment_status
FROM security.external_identities ei
JOIN security.users u ON u.user_id=ei.user_id
JOIN security.security_principals sp ON sp.principal_id=u.user_id
LEFT JOIN security.user_admin_role_assignments a
  ON a.user_id=u.user_id
 AND a.role_key='SuperAdmin'
 AND a.scope_type='PLATFORM'
 AND a.scope_id IS NULL
WHERE ei.provider='CLERK'
  AND ei.provider_subject='user_3I7FdD5Pkmydsp23OfjH9hBMxpN';
