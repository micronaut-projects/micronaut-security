package io.micronaut.docs.claimsaudience;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.claims.ClaimsAudienceProvider;
import jakarta.inject.Singleton;

import java.util.List;

@Requires(property = "spec.name", value = "claims-generation-docs")
//tag::clazz[]
@Singleton
class CustomClaimsAudienceProvider implements ClaimsAudienceProvider {

    @Override
    public List<String> audience() {
        return List.of("https://api.example.com");
    }
}
//end::clazz[]
