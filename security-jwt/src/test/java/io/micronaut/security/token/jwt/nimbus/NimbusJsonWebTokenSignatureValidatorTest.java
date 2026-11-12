package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.signature.rsa.RSASignature;
import io.micronaut.security.token.jwt.signature.secret.SecretSignature;
import io.micronaut.security.token.jwt.signature.secret.SecretSignatureConfiguration;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NimbusJsonWebTokenSignatureValidatorTest {

    private static final String SECRET = "test-fixture-not-a-secret-256-bits-long!!!";

    private static SecretSignature secretSignature(String secret) {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret(secret);
        return new SecretSignature(config);
    }

    private static SignedJWT tokenWithAlgorithm(String algorithmName) throws Exception {
        // Build the compact serialisation by hand so that Nimbus parses it into a SIGNED state
        // with whatever (possibly unknown) algorithm name the attacker chose in the header.
        JWSHeader header = new JWSHeader(new JWSAlgorithm(algorithmName));
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("sherlock").build();
        Base64URL signature = Base64URL.encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        String compact = header.toBase64URL() + "." + claims.toPayload().toBase64URL() + "." + signature;
        return SignedJWT.parse(compact);
    }

    @Test
    void knownAlgorithmSignedWithConfiguredSecretIsValid() throws Exception {
        SecretSignature signature = secretSignature(SECRET);
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(List.of(signature));

        SignedJWT signedJWT = signature.sign(new JWTClaimsSet.Builder().subject("sherlock").build());
        assertTrue(validator.validateSignature(SignedJWT.parse(signedJWT.serialize())));

        SignedJWT signedWithOtherSecret = secretSignature("other-test-fixture-not-a-secret-256-bits!!")
            .sign(new JWTClaimsSet.Builder().subject("sherlock").build());
        assertFalse(validator.validateSignature(SignedJWT.parse(signedWithOtherSecret.serialize())));
    }

    @Test
    void tokensWithDistinctUnknownAlgorithmsAreRejectedWithoutException() throws Exception {
        List<SignatureConfiguration> signatures = List.of(secretSignature(SECRET));
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(signatures);

        for (int i = 0; i < 1_000; i++) {
            SignedJWT token = tokenWithAlgorithm("ATTACKER-" + UUID.randomUUID());
            assertFalse(assertDoesNotThrow(() -> validator.validateSignature(token)));
        }
        // Well-known algorithms that the configured secret signature does not support must also be rejected.
        // ("none" is not covered here because Nimbus refuses to build a JWSHeader/SignedJWT with it at all.)
        for (String alg : List.of("RS256", "ES256", "PS256", "EdDSA")) {
            SignedJWT token = tokenWithAlgorithm(alg);
            assertFalse(assertDoesNotThrow(() -> validator.validateSignature(token)));
        }
    }

    @Test
    void validatorKeepsNoStateKeyedByTheTokenHeader() {
        // Regression guard: a value derived from the untrusted "alg" header must never be a key of an
        // unbounded structure held by the validator, otherwise a client sending a fresh algorithm name
        // per request can exhaust memory.
        List<Field> mapFields = Arrays.stream(NimbusJsonWebTokenSignatureValidator.class.getDeclaredFields())
            .filter(field -> Map.class.isAssignableFrom(field.getType()))
            .toList();
        assertTrue(mapFields.isEmpty(), "NimbusJsonWebTokenSignatureValidator must not hold a Map: " + mapFields);
    }

    private record RecordingSignature(String name, boolean supported, boolean verifies, List<String> calls)
        implements SignatureConfiguration {
        @Override
        public String supportedAlgorithmsMessage() {
            return name;
        }

        @Override
        public boolean supports(JWSAlgorithm algorithm) {
            return supported;
        }

        @Override
        public boolean verify(SignedJWT jwt) {
            calls.add(name);
            return verifies;
        }
    }

    @Test
    void configurationSupportingTheAlgorithmIsTriedFirstRegardlessOfConfiguredPosition() throws Exception {
        List<String> calls = new ArrayList<>();
        // RSA is configured first, HMAC second; the token is HS256, so HMAC must be tried first.
        SignatureConfiguration rsa = new RecordingSignature("rsa", false, false, calls);
        SignatureConfiguration hmac = new RecordingSignature("hmac", true, true, calls);
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(List.of(rsa, hmac));

        assertTrue(validator.validateSignature(tokenWithAlgorithm("HS256")));
        assertEquals(List.of("hmac"), calls);
    }

    @Test
    void nonSupportingConfigurationsAreStillTriedAfterSupportingOnesFailAndKeepConfiguredOrder() throws Exception {
        List<String> calls = new ArrayList<>();
        SignatureConfiguration rsa1 = new RecordingSignature("rsa1", false, false, calls);
        SignatureConfiguration hmac1 = new RecordingSignature("hmac1", true, false, calls);
        SignatureConfiguration rsa2 = new RecordingSignature("rsa2", false, true, calls);
        SignatureConfiguration hmac2 = new RecordingSignature("hmac2", true, false, calls);
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(List.of(rsa1, hmac1, rsa2, hmac2));

        assertTrue(validator.validateSignature(tokenWithAlgorithm("HS256")));
        assertEquals(List.of("hmac1", "hmac2", "rsa1", "rsa2"), calls);
    }

    @Test
    void allConfigurationsFailingRejectsTheTokenAfterTryingEveryOneInOrder() throws Exception {
        List<String> calls = new ArrayList<>();
        SignatureConfiguration rsa = new RecordingSignature("rsa", false, false, calls);
        SignatureConfiguration hmac = new RecordingSignature("hmac", true, false, calls);
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(List.of(rsa, hmac));

        assertFalse(validator.validateSignature(tokenWithAlgorithm("HS256")));
        assertEquals(List.of("hmac", "rsa"), calls);
    }

    /**
     * Delegates to a real {@link SignatureConfiguration} and records which configuration verified the token.
     */
    private record RecordingDelegate(String name, SignatureConfiguration delegate, List<String> calls)
        implements SignatureConfiguration {
        @Override
        public String supportedAlgorithmsMessage() {
            return delegate.supportedAlgorithmsMessage();
        }

        @Override
        public boolean supports(JWSAlgorithm algorithm) {
            return delegate.supports(algorithm);
        }

        @Override
        public boolean verify(SignedJWT jwt) throws JOSEException {
            calls.add(name);
            return delegate.verify(jwt);
        }
    }

    @Test
    void realRsaAndHmacConfigurationsAreTriedInAlgorithmOrderRegardlessOfConfiguredPosition() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSASignature rsa = new RSASignature(() -> (RSAPublicKey) keyPair.getPublic());
        SecretSignature hmac = secretSignature(SECRET);

        List<String> calls = new ArrayList<>();
        // RSA is configured first, HMAC second.
        NimbusJsonWebTokenSignatureValidator validator = new NimbusJsonWebTokenSignatureValidator(List.of(
            new RecordingDelegate("rsa", rsa, calls),
            new RecordingDelegate("hmac", hmac, calls)));

        // HS256 token: HMAC supports the algorithm and must be tried first, so RSA is never asked.
        SignedJWT hs256 = SignedJWT.parse(hmac.sign(new JWTClaimsSet.Builder().subject("sherlock").build()).serialize());
        assertTrue(validator.validateSignature(hs256));
        assertEquals(List.of("hmac"), calls);

        // RS256 token: RSA supports the algorithm and keeps its configured position.
        calls.clear();
        SignedJWT rs256 = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder().subject("sherlock").build());
        rs256.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
        assertTrue(validator.validateSignature(SignedJWT.parse(rs256.serialize())));
        assertEquals(List.of("rsa"), calls);

        // HS256 token signed with another secret: HMAC fails first, then RSA is still tried and fails too.
        calls.clear();
        SignedJWT forged = SignedJWT.parse(secretSignature("other-test-fixture-not-a-secret-256-bits!!")
            .sign(new JWTClaimsSet.Builder().subject("sherlock").build()).serialize());
        assertFalse(validator.validateSignature(forged));
        assertEquals(List.of("hmac", "rsa"), calls);
    }
}
