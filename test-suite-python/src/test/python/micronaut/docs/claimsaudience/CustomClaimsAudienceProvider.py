from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.security.token.claims import ClaimsAudienceProvider

AUDIENCE = ["https://api.example.com"]


@Requires(property="spec.name", value="claims-generation-docs")
# tag::clazz[]
@Singleton
class CustomClaimsAudienceProvider(ClaimsAudienceProvider):

    def audience(self) -> list[str]:
        return AUDIENCE
# end::clazz[]
