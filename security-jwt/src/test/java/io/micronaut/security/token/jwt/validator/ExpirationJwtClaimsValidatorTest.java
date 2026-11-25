package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExpirationJwtClaimsValidatorTest {

    private static final long ONE_HOUR_MILLIS = 60 * 60 * 1000L;

    @Test
    void validatesJwtClaimsSetAdapterBackedClaims() {
        ExpirationJwtClaimsValidator<Object> validator = new ExpirationJwtClaimsValidator<>();

        assertTrue(validator.validate(adapter(new Date(System.currentTimeMillis() + ONE_HOUR_MILLIS)), null));
        assertFalse(validator.validate(adapter(new Date(System.currentTimeMillis() - ONE_HOUR_MILLIS)), null));
        assertTrue(validator.validate(new JwtClaimsSetAdapter(new JWTClaimsSet.Builder().subject("sherlock").build()), null));
    }

    @Test
    void validatesMapClaims() {
        ExpirationJwtClaimsValidator<Object> validator = new ExpirationJwtClaimsValidator<>();

        assertTrue(validator.validate(mapClaims(new Date(System.currentTimeMillis() + ONE_HOUR_MILLIS)), null));
        assertFalse(validator.validate(mapClaims(new Date(System.currentTimeMillis() - ONE_HOUR_MILLIS)), null));
        // seconds since epoch, as found in a raw JWT payload
        assertTrue(validator.validate(new MapClaims(Map.of(Claims.EXPIRATION_TIME, (System.currentTimeMillis() + ONE_HOUR_MILLIS) / 1000L)), null));
        assertFalse(validator.validate(new MapClaims(Map.of(Claims.EXPIRATION_TIME, (System.currentTimeMillis() - ONE_HOUR_MILLIS) / 1000L)), null));
        assertTrue(validator.validate(new MapClaims(Map.of(Claims.SUBJECT, "sherlock")), null));
    }

    @Test
    void jwtClaimsSetUtilsReusesWrappedClaimsSet() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sherlock").build();
        assertSame(claimsSet, JWTClaimsSetUtils.jwtClaimsSetFromClaims(new JwtClaimsSetAdapter(claimsSet)));

        JWTClaimsSet built = JWTClaimsSetUtils.jwtClaimsSetFromClaims(new MapClaims(Map.of(Claims.SUBJECT, "sherlock")));
        assertEquals("sherlock", built.getSubject());
    }

    private static Claims adapter(Date expiration) {
        return new JwtClaimsSetAdapter(new JWTClaimsSet.Builder().subject("sherlock").expirationTime(expiration).build());
    }

    private static Claims mapClaims(Date expiration) {
        return new MapClaims(Map.of(Claims.SUBJECT, "sherlock", Claims.EXPIRATION_TIME, expiration));
    }
}
