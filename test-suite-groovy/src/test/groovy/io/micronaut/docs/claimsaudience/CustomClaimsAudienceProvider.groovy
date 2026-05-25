package io.micronaut.docs.claimsaudience

import io.micronaut.context.annotation.Requires
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "claims-generation-docs")
//tag::clazz[]
@Singleton
class CustomClaimsAudienceProvider implements ClaimsAudienceProvider {

    @Override
    List<String> audience() {
        ["https://api.example.com"]
    }
}
//end::clazz[]
