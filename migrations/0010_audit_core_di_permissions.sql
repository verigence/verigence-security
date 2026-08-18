-- Audit Core least-privilege DI permissions required by the approved Security OAuth contract.
-- Scope is intentionally limited to the two permission keys proven by Security PR #60.

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status)
VALUES
('di.document.read','di','document','read',NULL,'ACTIVE'),
('di.document.upload','di','document','upload',NULL,'ACTIVE')
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  status='ACTIVE';
