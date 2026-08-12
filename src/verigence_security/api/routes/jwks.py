from fastapi import APIRouter, Depends

from verigence_security.api.dependencies import token_service
from verigence_security.services.token_service import TokenService

router = APIRouter(tags=["Runtime Access"])


@router.get("/.well-known/jwks.json")
def jwks(tokens: TokenService = Depends(token_service)) -> dict[str, object]:
    return tokens.jwks()
