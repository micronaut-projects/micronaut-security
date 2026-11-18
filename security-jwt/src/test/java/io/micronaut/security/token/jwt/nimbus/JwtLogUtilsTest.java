package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The kid, alg and jti of a JWT are controlled by whoever sends the token. They must not allow forging log entries.
 */
class JwtLogUtilsTest {

    @Test
    void describeIncludesOnlyKidAlgAndJti() {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-1").build(),
                new JWTClaimsSet.Builder().subject("sherlock").jwtID("jti-123").claim("email", "john.doe@example.com").build());

        assertEquals("JWT [kid=kid-1, alg=RS256, jti=jti-123]", JwtLogUtils.describe(jwt));
    }

    @Test
    void describeReportsMissingKidAndJtiAsNull() {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
                new JWTClaimsSet.Builder().subject("sherlock").build());

        assertEquals("JWT [kid=null, alg=HS256, jti=null]", JwtLogUtils.describe(jwt));
    }

    @Test
    void describeOmitsJtiIfTheClaimsCannotBeParsed() throws Exception {
        Base64URL header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("kid-1").build().toBase64URL();
        SignedJWT jwt = new SignedJWT(header, Base64URL.encode("not json"), Base64URL.encode("signature"));

        assertEquals("JWT [kid=kid-1, alg=HS256, jti=null]", JwtLogUtils.describe(jwt));
    }

    @Test
    void describeReplacesLineBreaksSoThatALogEntryCannotBeForged() {
        String forged = "kid\r\n2026-01-01 00:00:00 INFO Signature verified for JWT";
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(new JWSAlgorithm("RS256\nforged")).keyID(forged).build(),
                new JWTClaimsSet.Builder().jwtID("jti forged\tvalue").build());

        assertEquals("JWT [kid=kid__2026-01-01 00:00:00 INFO Signature verified for JWT, alg=RS256_forged, jti=jti_forged_value]",
                JwtLogUtils.describe(jwt));
    }

    @Test
    void sanitizeTruncatesLongValues() {
        String sanitized = JwtLogUtils.sanitize("a".repeat(10_000));

        assertEquals("a".repeat(128) + "...", sanitized);
    }

    @Test
    void sanitizeKeepsNull() {
        assertNull(JwtLogUtils.sanitize(null));
    }
}
