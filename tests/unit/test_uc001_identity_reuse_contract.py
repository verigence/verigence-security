from pathlib import Path


def test_phase1_registration_blocks_only_active_or_suspended_user_contacts() -> None:
    source = Path("src/verigence_security/services/phase1_self_onboarding.py").read_text()
    assert "status IN ('ACTIVE','SUSPENDED')" in source
    assert "Email address belongs to an active or suspended user" in source
    assert "Mobile number belongs to an active or suspended user" in source


def test_uc001_identity_reuse_migration_matches_service_rule() -> None:
    migration = Path("migrations/0020_uc001_identity_reuse.sql").read_text()
    assert migration.count("status IN ('ACTIVE','SUSPENDED')") >= 2
    assert "uq_security_users_primary_email_ci" in migration
    assert "uq_security_users_primary_mobile_digits_active" in migration
