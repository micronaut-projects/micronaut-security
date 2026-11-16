package io.micronaut.security.token.jwt.signature.secret;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretSignatureVerifierReuseTest {

    private static final String SECRET = "pleaseChangeThisSecretForANewOne";
    private static final String OTHER_SECRET = "anotherSecretWhichIsLongEnoughToo";

    @Test
    @SuppressWarnings("removal")
    void verifierAndSignerAreReusedAcrossCallsAndInvalidatedBySetSecret() throws Exception {
        SecretSignature secretSignature = secretSignature(SECRET);
        assertNull(field(secretSignature, "verifier"));
        assertNull(field(secretSignature, "signer"));

        SignedJWT jwt = secretSignature.sign(new JWTClaimsSet.Builder().subject("sherlock").build());
        JWSSigner firstSigner = (JWSSigner) field(secretSignature, "signer");
        assertNotNull(firstSigner);

        assertTrue(secretSignature.verify(jwt));
        JWSVerifier firstVerifier = (JWSVerifier) field(secretSignature, "verifier");
        assertNotNull(firstVerifier);

        assertTrue(secretSignature.verify(jwt));
        assertSame(firstVerifier, field(secretSignature, "verifier"));

        secretSignature.sign(new JWTClaimsSet.Builder().subject("watson").build());
        assertSame(firstSigner, field(secretSignature, "signer"));

        secretSignature.setSecret(OTHER_SECRET);
        assertNull(field(secretSignature, "verifier"));
        assertNull(field(secretSignature, "signer"));

        // a token signed with the old secret no longer verifies, proving the new verifier uses the new secret
        assertFalse(secretSignature.verify(jwt));
        JWSVerifier secondVerifier = (JWSVerifier) field(secretSignature, "verifier");
        assertNotNull(secondVerifier);
        assertNotSame(firstVerifier, secondVerifier);

        SignedJWT jwtWithNewSecret = secretSignature.sign(new JWTClaimsSet.Builder().subject("sherlock").build());
        assertNotSame(firstSigner, field(secretSignature, "signer"));
        assertTrue(secretSignature.verify(jwtWithNewSecret));
        assertTrue(secretSignature(OTHER_SECRET).verify(jwtWithNewSecret));
    }

    @Test
    void tooShortSecretStillSurfacesAsJoseExceptionOnUse() {
        SecretSignature secretSignature = secretSignature("tooShort");
        assertThrows(JOSEException.class,
            () -> secretSignature.sign(new JWTClaimsSet.Builder().subject("sherlock").build()));
    }

    private static SecretSignature secretSignature(String secret) {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret(secret);
        return new SecretSignature(config);
    }

    private static Object field(SecretSignature secretSignature, String name) throws Exception {
        Field field = SecretSignature.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(secretSignature);
    }
}
