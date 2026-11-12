package io.micronaut.security.token.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryption;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.secret.SecretSignature;
import io.micronaut.security.token.jwt.signature.secret.SecretSignatureConfiguration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The setters are deprecated for removal, but their behaviour must be preserved until they are removed.
 */
@SuppressWarnings("removal")
class DeprecatedSettersTest {

    private static final String SECRET = "pleaseChangeThisSecretForANewOne";
    private static final String OTHER_SECRET = "anotherSecretWhichIsLongEnoughTo";
    // HS512 requires a secret of at least 512 bits
    private static final String SIGNATURE_SECRET = SECRET + SECRET;
    private static final String OTHER_SIGNATURE_SECRET = OTHER_SECRET + OTHER_SECRET;

    @Test
    void secretSignatureDeprecatedSettersStillWork() throws Exception {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret(SIGNATURE_SECRET);
        SecretSignature signature = new SecretSignature(config);
        assertEquals(SIGNATURE_SECRET, signature.getSecret());
        assertEquals(JWSAlgorithm.HS256, signature.getAlgorithm());

        signature.setAlgorithm(JWSAlgorithm.HS512);
        assertEquals(JWSAlgorithm.HS512, signature.getAlgorithm());
        SignedJWT jwt = signature.sign(new JWTClaimsSet.Builder().subject("sherlock").build());
        assertEquals(JWSAlgorithm.HS512, jwt.getHeader().getAlgorithm());
        assertTrue(signature.verify(jwt));

        signature.setSecret(OTHER_SIGNATURE_SECRET);
        assertEquals(OTHER_SIGNATURE_SECRET, signature.getSecret());
        assertFalse(signature.verify(jwt));
        assertTrue(signature.verify(signature.sign(new JWTClaimsSet.Builder().subject("watson").build())));
    }

    @Test
    void secretEncryptionDeprecatedSettersStillWork() throws Exception {
        SecretEncryptionConfiguration config = new SecretEncryptionConfiguration("generator");
        config.setSecret(SECRET);
        config.setJweAlgorithm(JWEAlgorithm.DIR);
        config.setEncryptionMethod(EncryptionMethod.A256GCM);
        SecretEncryption encryption = new SecretEncryption(config);
        assertEquals(SECRET, encryption.getSecret());

        encryption.setAlgorithm(JWEAlgorithm.A256KW);
        encryption.setMethod(EncryptionMethod.A128CBC_HS256);
        encryption.setSecret(OTHER_SECRET);
        assertEquals(JWEAlgorithm.A256KW, encryption.getAlgorithm());
        assertEquals(EncryptionMethod.A128CBC_HS256, encryption.getMethod());
        assertEquals(OTHER_SECRET, encryption.getSecret());

        String token = encryption.encrypt(new PlainJWT(new JWTClaimsSet.Builder().subject("sherlock").build()));
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
        assertEquals(JWEAlgorithm.A256KW, encryptedJWT.getHeader().getAlgorithm());
        assertEquals(EncryptionMethod.A128CBC_HS256, encryptedJWT.getHeader().getEncryptionMethod());
        encryption.decrypt(encryptedJWT);
        assertEquals("sherlock", encryptedJWT.getJWTClaimsSet().getSubject());
    }
}
