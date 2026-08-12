from fastapi import APIRouter, Depends

from verigence_security.adapters.identity import DevMockIdentityProvider
from verigence_security.api.dependencies import repository
from verigence_security.api.schemas import DevMockTokenRequest
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository

router = APIRouter(prefix="/security/v1/dev", tags=["DEV"])


@router.post("/mock-auth/token")
def mock_token(
    body: DevMockTokenRequest,
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, str]:
    provider_subject = repo.ensure_dev_mock_identity(str(body.userId))
    token, exp = DevMockIdentityProvider(settings).issue(provider_subject)
    return {"mockIdentityToken": token, "expiresAt": exp.isoformat()}
