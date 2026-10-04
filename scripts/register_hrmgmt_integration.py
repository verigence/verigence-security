"""Register (or re-register) the HR service identity in Security. Prints no secrets."""
import os
import sys
import uuid
from datetime import datetime, timezone

import psycopg
from argon2 import PasswordHasher

INTEGRATION_KEY = "hrmgmt"
CLIENT_ID = "hrmgmt-dev"


def main() -> int:
    db_url = os.environ.get("DATABASE_URL", "").strip()
    client_secret = os.environ.get("HRMGMT_CLIENT_SECRET", "")
    if not db_url or len(client_secret) < 32:
        print("DATABASE_URL and a client secret of at least 32 characters are required")
        return 1
    for prefix in ("postgresql+psycopg://", "postgresql+asyncpg://", "postgres://"):
        if db_url.startswith(prefix):
            db_url = "postgresql://" + db_url[len(prefix):]
    secret_hash = PasswordHasher().hash(client_secret)
    now = datetime.now(timezone.utc)
    with psycopg.connect(db_url, connect_timeout=20) as conn:
        cur = conn.cursor()
        cur.execute(
            "select user_id from security.user_admin_role_assignments "
            "where role_key='SuperAdmin' and scope_type='PLATFORM' and status='ACTIVE' limit 1"
        )
        row = cur.fetchone()
        if not row:
            print("no active SuperAdmin found")
            return 1
        super_admin = row[0]
        cur.execute("select principal_id from security.service_integrations where integration_key=%s", (INTEGRATION_KEY,))
        row = cur.fetchone()
        if row:
            principal_id = row[0]
            print("integration hrmgmt: already registered")
        else:
            principal_id = uuid.uuid4()
            cur.execute(
                "insert into security.security_principals values (%s,'SERVICE_INTEGRATION',%s,'ACTIVE',%s,%s)",
                (principal_id, INTEGRATION_KEY, now, now),
            )
            cur.execute(
                "insert into security.service_integrations (principal_id,integration_key,description,created_at_utc) "
                "values (%s,%s,%s,%s)",
                (principal_id, INTEGRATION_KEY, "Verigence HR service (HRMgmt)", now),
            )
            print("integration hrmgmt: registered")
        cur.execute("select credential_id from security.principal_credentials where client_id=%s", (CLIENT_ID,))
        row = cur.fetchone()
        if row:
            cur.execute(
                "update security.principal_credentials set secret_hash=%s,status='ACTIVE',valid_to_utc=NULL "
                "where credential_id=%s",
                (secret_hash, row[0]),
            )
            print("credential hrmgmt-dev: secret replaced")
        else:
            cur.execute(
                "insert into security.principal_credentials "
                "(credential_id,principal_id,client_id,secret_hash,status,valid_from_utc,created_by_user_id,created_at_utc) "
                "values (%s,%s,%s,%s,'ACTIVE',now() - interval '5 minutes',%s,%s)",
                (uuid.uuid4(), principal_id, CLIENT_ID, secret_hash, super_admin, now),
            )
            print("credential hrmgmt-dev: created")
        conn.commit()
    return 0


sys.exit(main())
