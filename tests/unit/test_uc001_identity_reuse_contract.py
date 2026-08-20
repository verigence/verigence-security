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


def test_uc001_start_route_uses_restart_aware_service() -> None:
    route_source = Path("src/verigence_security/api/routes/global_users.py").read_text()
    restart_source = Path("src/verigence_security/services/uc001_self_onboarding.py").read_text()
    assert "UC001SelfOnboardingService(session).start(" in route_source
    assert "SET status='CANCELLED'" in restart_source
    assert "status IN ('CANCELLED','EXPIRED')" in restart_source
    assert "clerk.delete_user(clerk_user_id)" in restart_source
