package io.micronaut.docs.claimsaudience;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.claims.ClaimsAudienceProvider;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "claims-generation-docs")
@MicronautTest(startApplication = false)
class CustomClaimsAudienceProviderTest {

    @Inject
    ClaimsAudienceProvider claimsAudienceProvider;

    @Inject
    ClaimsGenerator claimsGenerator;

    @Test
    void customClaimsAudienceProviderSuppliesJwtAudienceClaim() {
        Map<String, Object> claims = claimsGenerator.generateClaims(Authentication.build("sherlock"), 3600);

        assertEquals(List.of("https://api.example.com"), claimsAudienceProvider.audience());
        assertEquals(List.of("https://api.example.com"), claims.get(Claims.AUDIENCE));
    }
}
