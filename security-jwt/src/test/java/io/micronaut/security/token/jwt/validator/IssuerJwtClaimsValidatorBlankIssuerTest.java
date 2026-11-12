package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * When {@code micronaut.security.token.jwt.claims-validators.issuer} is present but bound to {@code null} (e.g. {@code issuer:} in
 * YAML), empty or blank, the validator exists and must fail closed instead of accepting any {@code iss} claim.
 */
class IssuerJwtClaimsValidatorBlankIssuerTest {

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void presentButValuelessIssuerRejectsEveryToken(String configuredIssuer) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-0123456789");
        configuration.put(IssuerJwtClaimsValidator.ISSUER_PROP, configuredIssuer);
        try (ApplicationContext context = ApplicationContext.run(configuration)) {
            assertTrue(context.containsBean(IssuerJwtClaimsValidator.class));
            for (String iss : new String[] {"https://attacker.example", "", "/"}) {
                Map<String, Object> claims = new HashMap<>();
                claims.put(Claims.SUBJECT, "alice");
                claims.put(Claims.ISSUER, iss);
                String jwt = context.getBean(JwtTokenGenerator.class).generateToken(claims).orElseThrow();
                @SuppressWarnings("unchecked")
                JsonWebTokenValidator<JWT, Object> validator = context.getBean(JsonWebTokenValidator.class);
                assertFalse(validator.validate(jwt, null).isPresent(), () -> "iss '" + iss + "' must be rejected when the configured issuer is [" + configuredIssuer + "]");
            }
        }
    }
}
