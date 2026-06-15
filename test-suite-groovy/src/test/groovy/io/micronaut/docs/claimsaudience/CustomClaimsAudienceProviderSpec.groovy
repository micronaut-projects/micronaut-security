package io.micronaut.docs.claimsaudience

import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.Claims
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import io.micronaut.security.token.claims.ClaimsGenerator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "claims-generation-docs")
@MicronautTest(startApplication = false)
class CustomClaimsAudienceProviderSpec extends Specification {

    @Inject
    ClaimsAudienceProvider claimsAudienceProvider

    @Inject
    ClaimsGenerator claimsGenerator

    void "custom claims audience provider supplies JWT audience claim"() {
        when:
        Map<String, Object> claims = claimsGenerator.generateClaims(Authentication.build("sherlock"), 3600)

        then:
        claimsAudienceProvider.audience() == ["https://api.example.com"]
        claims[Claims.AUDIENCE] == ["https://api.example.com"]
    }
}
