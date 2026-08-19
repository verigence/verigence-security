-- Verigence Security v2 — approved Phase-1 module permissions and operating-role defaults
-- Canonical permission NAMES only; no Audit Core/DI database identifiers are stored.
-- Additive/idempotent: existing permission lifecycle/default rows are not overwritten.

BEGIN;

WITH approved_permissions(permission_key,module_key,resource_key,action_key) AS (
  VALUES
  ('audit.project.read','audit','project','read'),
  ('audit.project.update','audit','project','update'),
  ('audit.project.assignment.manage','audit','project.assignment','manage'),
  ('audit.master.read','audit','master','read'),
  ('audit.master.write','audit','master','write'),
  ('audit.master.publish','audit','master','publish'),
  ('audit.customer.read','audit','customer','read'),
  ('audit.customer.write','audit','customer','write'),
  ('audit.journey.create','audit','journey','create'),
  ('audit.journey.read','audit','journey','read'),
  ('audit.journey.update','audit','journey','update'),
  ('audit.journey.submit','audit','journey','submit'),
  ('audit.evidence.read','audit','evidence','read'),
  ('audit.evidence.upload','audit','evidence','upload'),
  ('audit.evidence.refresh','audit','evidence','refresh'),
  ('audit.payment.read','audit','payment','read'),
  ('audit.payment.write','audit','payment','write'),
  ('audit.payment.verify','audit','payment','verify'),
  ('audit.delivery.read','audit','delivery','read'),
  ('audit.delivery.write','audit','delivery','write'),
  ('audit.delivery.verify','audit','delivery','verify'),
  ('audit.trade_in.read','audit','trade_in','read'),
  ('audit.trade_in.write','audit','trade_in','write'),
  ('audit.trade_in.verify','audit','trade_in','verify'),
  ('audit.finding.read','audit','finding','read'),
  ('audit.finding.create','audit','finding','create'),
  ('audit.finding.update','audit','finding','update'),
  ('audit.finding.resolve','audit','finding','resolve'),
  ('audit.review.read','audit','review','read'),
  ('audit.review.decide','audit','review','decide'),
  ('audit.work.read','audit','work','read'),
  ('audit.work.update','audit','work','update'),
  ('audit.work.manage','audit','work','manage'),
  ('audit.daily_ops.read','audit','daily_ops','read'),
  ('audit.daily_ops.execute','audit','daily_ops','execute'),
  ('audit.daily_ops.review','audit','daily_ops','review'),
  ('audit.crm.read','audit','crm','read'),
  ('audit.crm.execute','audit','crm','execute'),
  ('audit.crm.manage','audit','crm','manage'),
  ('audit.escalation.read','audit','escalation','read'),
  ('audit.escalation.manage','audit','escalation','manage'),
  ('audit.analytics.read','audit','analytics','read'),
  ('audit.audit_trail.read','audit','audit_trail','read'),
  ('di.document.content.read','di','document.content','read'),
  ('di.document.fields.read','di','document.fields','read'),
  ('di.document.quality.read','di','document.quality','read'),
  ('di.document.read','di','document','read'),
  ('di.document.upload','di','document','upload'),
  ('di.entity_link.read','di','entity_link','read'),
  ('di.entity_link.write','di','entity_link','write'),
  ('di.extraction_config.publish','di','extraction_config','publish'),
  ('di.extraction_config.read','di','extraction_config','read'),
  ('di.extraction_config.write','di','extraction_config','write'),
  ('di.operations.read','di','operations','read'),
  ('di.quality_config.read','di','quality_config','read'),
  ('di.quality_config.write','di','quality_config','write'),
  ('di.requirement_profile.assign','di','requirement_profile','assign'),
  ('di.requirement_profile.publish','di','requirement_profile','publish'),
  ('di.requirement_profile.read','di','requirement_profile','read'),
  ('di.requirement_profile.write','di','requirement_profile','write'),
  ('di.subject.create','di','subject','create'),
  ('di.subject.read','di','subject','read'),
  ('di.tenant_config.read','di','tenant_config','read'),
  ('di.tenant_config.write','di','tenant_config','write'),
  ('di.unassigned_document.read','di','unassigned_document','read'),
  ('di.verification.read','di','verification','read'),
  ('di.verification.write','di','verification','write')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
SELECT permission_key,module_key,resource_key,action_key,NULL,'ACTIVE',permission_key,
       CASE module_key WHEN 'audit' THEN 'audit-2.1' ELSE 'di-phase1-approved' END,
       CURRENT_TIMESTAMP
FROM approved_permissions
ON CONFLICT (permission_key) DO NOTHING;

DO $$
DECLARE invalid_count integer;
BEGIN
  WITH required(permission_key) AS (
    SELECT unnest(ARRAY['audit.analytics.read','audit.audit_trail.read','audit.crm.execute','audit.crm.manage','audit.crm.read','audit.customer.read','audit.customer.write','audit.daily_ops.execute','audit.daily_ops.read','audit.daily_ops.review','audit.delivery.read','audit.delivery.verify','audit.delivery.write','audit.escalation.manage','audit.escalation.read','audit.evidence.read','audit.evidence.refresh','audit.evidence.upload','audit.finding.create','audit.finding.read','audit.finding.resolve','audit.finding.update','audit.journey.create','audit.journey.read','audit.journey.submit','audit.journey.update','audit.master.read','audit.master.write','audit.payment.read','audit.payment.verify','audit.payment.write','audit.project.assignment.manage','audit.project.read','audit.project.update','audit.review.decide','audit.review.read','audit.trade_in.read','audit.trade_in.verify','audit.trade_in.write','audit.work.manage','audit.work.read','audit.work.update','di.document.content.read','di.document.fields.read','di.document.quality.read','di.document.read','di.document.upload','di.entity_link.read','di.entity_link.write','di.extraction_config.read','di.operations.read','di.quality_config.read','di.requirement_profile.read','di.subject.create','di.subject.read','di.tenant_config.read','di.unassigned_document.read','di.verification.read','di.verification.write']::varchar[])
  )
  SELECT count(*) INTO invalid_count
  FROM required r
  LEFT JOIN security.permissions p ON p.permission_key=r.permission_key
  WHERE p.permission_key IS NULL OR p.status <> 'ACTIVE';

  IF invalid_count <> 0 THEN
    RAISE EXCEPTION
      'Approved Phase-1 operating-role defaults reference % missing/non-ACTIVE permission(s)',
      invalid_count;
  END IF;
END $$;

WITH role_bundles(role_key,permission_keys) AS (
  VALUES
  ('PC',ARRAY['audit.project.read','audit.master.read','audit.customer.read','audit.customer.write','audit.journey.create','audit.journey.read','audit.journey.update','audit.journey.submit','audit.evidence.read','audit.evidence.upload','audit.evidence.refresh','audit.payment.read','audit.payment.write','audit.delivery.read','audit.delivery.write','audit.trade_in.read','audit.trade_in.write','audit.finding.read','audit.finding.create','audit.work.read','audit.work.update','audit.daily_ops.read','audit.daily_ops.execute','di.subject.create','di.subject.read','di.document.upload','di.document.read','di.document.content.read','di.document.fields.read','di.document.quality.read','di.entity_link.read','di.entity_link.write']::varchar[]),
  ('TL',ARRAY['audit.project.read','audit.master.read','audit.customer.read','audit.journey.read','audit.evidence.read','audit.evidence.refresh','audit.payment.read','audit.payment.verify','audit.delivery.read','audit.delivery.verify','audit.trade_in.read','audit.trade_in.verify','audit.finding.read','audit.finding.create','audit.finding.update','audit.review.read','audit.review.decide','audit.work.read','audit.work.update','audit.work.manage','audit.daily_ops.read','audit.daily_ops.review','audit.escalation.read','audit.analytics.read','di.subject.read','di.document.read','di.document.content.read','di.document.fields.read','di.document.quality.read','di.verification.read','di.verification.write','di.operations.read']::varchar[]),
  ('PM',ARRAY['audit.project.read','audit.project.update','audit.project.assignment.manage','audit.master.read','audit.customer.read','audit.journey.read','audit.evidence.read','audit.evidence.refresh','audit.payment.read','audit.payment.verify','audit.delivery.read','audit.delivery.verify','audit.trade_in.read','audit.trade_in.verify','audit.finding.read','audit.finding.create','audit.finding.update','audit.finding.resolve','audit.review.read','audit.review.decide','audit.work.read','audit.work.update','audit.work.manage','audit.daily_ops.read','audit.daily_ops.review','audit.crm.read','audit.crm.manage','audit.escalation.read','audit.escalation.manage','audit.analytics.read','audit.audit_trail.read','di.subject.read','di.document.read','di.document.content.read','di.document.fields.read','di.document.quality.read','di.verification.read','di.verification.write','di.operations.read']::varchar[]),
  ('CRM',ARRAY['audit.project.read','audit.customer.read','audit.journey.read','audit.evidence.read','audit.finding.read','audit.work.read','audit.work.update','audit.crm.read','audit.crm.execute','audit.escalation.read','di.subject.read','di.document.read','di.document.content.read','di.document.fields.read','di.document.quality.read']::varchar[]),
  ('Executive',ARRAY['audit.project.read','audit.master.read','audit.customer.read','audit.journey.read','audit.evidence.read','audit.payment.read','audit.delivery.read','audit.trade_in.read','audit.finding.read','audit.review.read','audit.work.read','audit.daily_ops.read','audit.crm.read','audit.escalation.read','audit.analytics.read','audit.audit_trail.read','audit.project.update','audit.master.write','audit.customer.write','audit.journey.update','audit.payment.write','audit.delivery.write','audit.trade_in.write','audit.finding.update','audit.work.update','di.subject.read','di.document.read','di.document.content.read','di.document.fields.read','di.document.quality.read','di.verification.read','di.entity_link.read','di.operations.read','di.unassigned_document.read','di.requirement_profile.read','di.extraction_config.read','di.quality_config.read','di.tenant_config.read']::varchar[])
),
approved_defaults AS (
  SELECT role_key,unnest(permission_keys) AS permission_key
  FROM role_bundles
)
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,
       CASE WHEN permission_key LIKE 'audit.%' THEN 'audit-2.1'
            ELSE 'di-phase1-approved' END,
       'ACTIVE',CURRENT_TIMESTAMP
FROM approved_defaults
ON CONFLICT (role_key,permission_key) DO NOTHING;

COMMIT;
