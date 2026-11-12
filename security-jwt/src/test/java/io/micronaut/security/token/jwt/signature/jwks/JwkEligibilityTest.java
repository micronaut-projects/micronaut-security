package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A JWK is only used to verify a signature if its {@code use}, {@code key_ops} and {@code alg} allow it.
 * Every key in the set shares the same Key ID so that matching by {@code kid} alone would select all of them.
 */
class JwkEligibilityTest {

    private static final String KID = "shared";

    private static RSAKey sigKey;
    private static RSAKey encKey;
    private static RSAKey rs512Key;
    private static RSAKey encryptOpsKey;
    private static JWKSet jwkSet;
    private static final JwkValidator VALIDATOR = new DefaultJwkValidator();

    @BeforeAll
    static void setup() throws Exception {
        sigKey = new RSAKeyGenerator(2048).keyID(KID).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        encKey = new RSAKeyGenerator(2048).keyID(KID).keyUse(KeyUse.ENCRYPTION).generate();
        rs512Key = new RSAKeyGenerator(2048).keyID(KID).algorithm(JWSAlgorithm.RS512).generate();
        encryptOpsKey = new RSAKeyGenerator(2048).keyID(KID).keyOperations(Set.of(KeyOperation.ENCRYPT)).generate();
        jwkSet = new JWKSet(List.of(
            (JWK) sigKey.toPublicJWK(),
            encKey.toPublicJWK(),
            rs512Key.toPublicJWK(),
            encryptOpsKey.toPublicJWK()));
    }

    @Test
    void onlyTheSignatureKeyMatchesTheToken() throws Exception {
        SignedJWT jwt = sign(sigKey, JWSAlgorithm.RS256, KID);

        List<JWK> matches = JwksSignatureUtils.matches(jwt, jwkSet, null);

        assertEquals(1, matches.size());
        assertEquals(sigKey.toPublicJWK(), matches.get(0));
    }

    @Test
    void onlyTheSignatureKeyMatchesWhenTheTokenHasNoKid() throws Exception {
        SignedJWT jwt = sign(sigKey, JWSAlgorithm.RS256, null);

        List<JWK> matches = JwksSignatureUtils.matches(jwt, jwkSet, KeyType.RSA);

        assertEquals(1, matches.size());
        assertEquals(sigKey.toPublicJWK(), matches.get(0));
    }

    @Test
    void tokenSignedWithTheSignatureKeyVerifies() throws Exception {
        SignedJWT jwt = sign(sigKey, JWSAlgorithm.RS256, KID);

        assertTrue(JwksSignatureUtils.verify(jwt, jwkSet, VALIDATOR));
    }

    @Test
    void tokenSignedWithTheEncryptionKeyIsRejected() throws Exception {
        SignedJWT jwt = sign(encKey, JWSAlgorithm.RS256, KID);

        assertFalse(JwksSignatureUtils.verify(jwt, jwkSet, VALIDATOR));
        assertFalse(VALIDATOR.validate(jwt, encKey.toPublicJWK()), "validator must not use a use=enc key even when handed directly");
    }

    @Test
    void tokenSignedWithTheKeyBoundToAnotherAlgorithmIsRejected() throws Exception {
        SignedJWT jwt = sign(rs512Key, JWSAlgorithm.RS256, KID);

        assertFalse(JwksSignatureUtils.verify(jwt, jwkSet, VALIDATOR));
        assertFalse(VALIDATOR.validate(jwt, rs512Key.toPublicJWK()), "validator must not use an alg=RS512 key for an RS256 token");
    }

    @Test
    void tokenSignedWithTheKeyWithoutVerifyOperationIsRejected() throws Exception {
        SignedJWT jwt = sign(encryptOpsKey, JWSAlgorithm.RS256, KID);

        assertFalse(JwksSignatureUtils.verify(jwt, jwkSet, VALIDATOR));
        assertFalse(VALIDATOR.validate(jwt, encryptOpsKey.toPublicJWK()), "validator must not use a key_ops=[encrypt] key");
    }

    @Test
    void keysWithoutUseKeyOpsAndAlgRemainEligible() throws Exception {
        RSAKey bare = new RSAKeyGenerator(2048).keyID("bare").generate();
        SignedJWT jwt = sign(bare, JWSAlgorithm.RS256, "bare");

        assertTrue(JwksSignatureUtils.isEligibleForVerification(bare.toPublicJWK(), JWSAlgorithm.RS256));
        assertTrue(JwksSignatureUtils.verify(jwt, new JWKSet(bare.toPublicJWK()), VALIDATOR));
    }

    @Test
    void keyOpsContainingVerifyAmongOthersRemainsEligible() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("ops").keyOperations(Set.of(KeyOperation.VERIFY, KeyOperation.ENCRYPT)).generate();
        SignedJWT jwt = sign(key, JWSAlgorithm.RS256, "ops");

        assertTrue(JwksSignatureUtils.isEligibleForVerification(key.toPublicJWK(), JWSAlgorithm.RS256));
        assertTrue(JwksSignatureUtils.verify(jwt, new JWKSet(key.toPublicJWK()), VALIDATOR));
    }

    @Test
    void keyBoundToTheTokenAlgorithmIsEligible() throws Exception {
        SignedJWT jwt = sign(rs512Key, JWSAlgorithm.RS512, KID);

        assertTrue(JwksSignatureUtils.isEligibleForVerification(rs512Key.toPublicJWK(), JWSAlgorithm.RS512));
        assertTrue(JwksSignatureUtils.verify(jwt, jwkSet, VALIDATOR));
    }

    private static SignedJWT sign(RSAKey key, JWSAlgorithm algorithm, String kid) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (kid != null) {
            header = header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().subject("sherlock").build());
        jwt.sign(new RSASSASigner(key));
        return jwt;
    }
}
