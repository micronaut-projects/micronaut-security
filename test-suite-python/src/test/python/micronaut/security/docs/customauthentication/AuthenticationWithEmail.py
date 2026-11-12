from dataclasses import dataclass

from micronaut.security.authentication import Authentication
from micronaut.serde.annotation import Serdeable


@Serdeable
@dataclass
class AuthenticationWithEmail:
    username: str
    email: str | None = None

    @staticmethod
    def of(authentication: Authentication) -> "AuthenticationWithEmail":
        obj = authentication.getAttributes().get("email")
        email = None if obj is None else str(obj)
        return AuthenticationWithEmail(authentication.getName(), email)
