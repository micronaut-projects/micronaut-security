package io.micronaut.security.token.jwt.nimbus;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NimbusJsonWebTokenEncryptionTest {

    @Test
    void decryptReturnsEmptyWithoutEncryptionConfigurationRegardlessOfLogLevel() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();
        EncryptedJWT jwt = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM),
            new JWTClaimsSet.Builder().subject("john").build());
        jwt.encrypt(new RSAEncrypter(rsaKey));
        String serialized = jwt.serialize();

        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(Collections.emptyList());
        Logger logger = (Logger) LoggerFactory.getLogger(NimbusJsonWebTokenEncryption.class);
        Level original = logger.getLevel();
        try {
            logger.setLevel(Level.DEBUG);
            Optional<SignedJWT> debugResult = encryption.decrypt(EncryptedJWT.parse(serialized));
            logger.setLevel(Level.INFO);
            Optional<SignedJWT> infoResult = encryption.decrypt(EncryptedJWT.parse(serialized));

            assertTrue(debugResult.isEmpty());
            assertTrue(infoResult.isEmpty());
            assertEquals(debugResult, infoResult);
        } finally {
            logger.setLevel(original);
        }
    }
}
