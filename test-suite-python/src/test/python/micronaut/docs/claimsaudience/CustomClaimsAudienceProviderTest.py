from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property
from micronaut.security.authentication import Authentication
from micronaut.security.token import Claims
from micronaut.security.token.claims import ClaimsAudienceProvider, ClaimsGenerator
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="claims-generation-docs")
@MicronautTest(startApplication=False)
class CustomClaimsAudienceProviderTest:
    claimsAudienceProvider: Annotated[ClaimsAudienceProvider, Inject]
    claimsGenerator: Annotated[ClaimsGenerator, Inject]

    @Test
    def test_custom_claims_audience_provider_supplies_jwt_audience_claim(self):
        claims = self.claimsGenerator.generateClaims(Authentication.build("sherlock"), 3600)

        assert list(self.claimsAudienceProvider.audience()) == ["https://api.example.com"]
        assert list(claims.get(Claims.AUDIENCE)) == ["https://api.example.com"]
