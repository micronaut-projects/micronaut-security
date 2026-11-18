package io.micronaut.security.token.jwt.nimbus;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryption;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NimbusJsonWebTokenEncryptionTest {

    private static final String SECRET = "pleaseChangeThisSecretForANewOne";
    private static final String OTHER_SECRET = "anotherSecretWhichIsAlso32Bytes!";
    private static final String SUBJECT = "john";

    @ParameterizedTest
    @ValueSource(strings = {"DEBUG", "INFO"})
    void decryptReturnsEmptyWithoutEncryptionConfiguration(String level) throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(Collections.emptyList());
        Logger logger = (Logger) LoggerFactory.getLogger(NimbusJsonWebTokenEncryption.class);
        Level original = logger.getLevel();
        try {
            logger.setLevel(Level.valueOf(level));

            assertTrue(encryption.decrypt(encryptedSignedJwt(SECRET)).isEmpty());
        } finally {
            logger.setLevel(original);
        }
    }

    @Test
    void decryptReturnsTheNestedSignedJwt() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(List.of(secretEncryption(SECRET)));

        Optional<SignedJWT> result = encryption.decrypt(encryptedSignedJwt(SECRET));

        assertTrue(result.isPresent());
        assertEquals(SUBJECT, result.get().getJWTClaimsSet().getSubject());
    }

    @Test
    void decryptFallsBackToTheNextConfigurationWhenOneFails() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(
            List.of(secretEncryption(OTHER_SECRET), secretEncryption(SECRET)));

        Optional<SignedJWT> result = encryption.decrypt(encryptedSignedJwt(SECRET));

        assertTrue(result.isPresent());
        assertEquals(SUBJECT, result.get().getJWTClaimsSet().getSubject());
    }

    @Test
    void decryptReturnsEmptyWhenNoConfigurationDecrypts() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(List.of(secretEncryption(OTHER_SECRET)));

        assertTrue(encryption.decrypt(encryptedSignedJwt(SECRET)).isEmpty());
    }

    @Test
    void decryptTriesConfigurationsSupportingTheHeaderFirst() throws Exception {
        List<String> attempts = new ArrayList<>();
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(List.of(
            new FailingEncryptionConfiguration("unsupported", false, attempts),
            new FailingEncryptionConfiguration("supported", true, attempts)));

        assertTrue(encryption.decrypt(encryptedSignedJwt(SECRET)).isEmpty());
        assertEquals(List.of("supported", "unsupported"), attempts);
    }

    @Test
    void decryptReturnsEmptyWhenThePayloadIsNotASignedJwt() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(
            List.of(secretEncryption(SECRET), secretEncryption(OTHER_SECRET)));
        EncryptedJWT jwt = new EncryptedJWT(header(), claims());
        jwt.encrypt(new DirectEncrypter(SECRET.getBytes(StandardCharsets.UTF_8)));

        assertTrue(encryption.decrypt(EncryptedJWT.parse(jwt.serialize())).isEmpty());
    }

    private static EncryptedJWT encryptedSignedJwt(String secret) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims());
        signedJWT.sign(new MACSigner(SECRET));
        JWEObject jwe = new JWEObject(header(), new Payload(signedJWT));
        jwe.encrypt(new DirectEncrypter(secret.getBytes(StandardCharsets.UTF_8)));
        return EncryptedJWT.parse(jwe.serialize());
    }

    private static JWEHeader header() {
        return new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build();
    }

    private static JWTClaimsSet claims() {
        return new JWTClaimsSet.Builder().subject(SUBJECT).build();
    }

    private static SecretEncryption secretEncryption(String secret) {
        SecretEncryptionConfiguration configuration = new SecretEncryptionConfiguration("test");
        configuration.setJweAlgorithm(JWEAlgorithm.DIR);
        configuration.setEncryptionMethod(EncryptionMethod.A256GCM);
        configuration.setSecret(secret);
        return new SecretEncryption(configuration);
    }

    private record FailingEncryptionConfiguration(String name,
                                                  boolean supported,
                                                  List<String> attempts) implements EncryptionConfiguration {
        @Override
        public boolean supports(JWEAlgorithm algorithm, EncryptionMethod method) {
            return supported;
        }

        @Override
        public String supportedAlgorithmsMessage() {
            return name;
        }

        @Override
        public String encrypt(JWT jwt) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void decrypt(EncryptedJWT encryptedJWT) throws JOSEException {
            attempts.add(name);
            throw new JOSEException(name);
        }
    }
}
