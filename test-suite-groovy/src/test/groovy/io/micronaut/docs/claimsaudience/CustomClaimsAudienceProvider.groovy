package io.micronaut.docs.claimsaudience

import io.micronaut.context.annotation.Requires
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "claims-generation-docs")
//tag::clazz[]
@Singleton
class CustomClaimsAudienceProvider implements ClaimsAudienceProvider {
    private static final ArrayList<String> AUDIENCE = ["https://api.example.com"]

    @Override
    List<String> audience() {
        AUDIENCE
    }
}
//end::clazz[]
