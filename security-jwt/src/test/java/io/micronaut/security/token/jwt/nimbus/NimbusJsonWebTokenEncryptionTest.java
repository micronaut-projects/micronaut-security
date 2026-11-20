package io.micronaut.security.token.jwt.nimbus;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryption;
import io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.OTHER_ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.SUBJECT;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.nestedJwe;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link NimbusJsonWebTokenEncryption}. The parser-level JWE scenarios (no encryption
 * configurations, undecryptable JWE, non-JWS payload with several configurations) are covered by the
 * {@code NimbusJsonWebTokenParser*Test} classes.
 */
class NimbusJsonWebTokenEncryptionTest {

    @Test
    void decryptFallsBackToTheNextConfigurationWhenOneFails() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(
            List.of(secretEncryption(OTHER_ENCRYPTION_SECRET), secretEncryption(ENCRYPTION_SECRET)));

        Optional<SignedJWT> result = encryption.decrypt(EncryptedJWT.parse(nestedJwe(ENCRYPTION_SECRET)));

        assertTrue(result.isPresent());
        assertEquals(SUBJECT, result.get().getJWTClaimsSet().getSubject());
    }

    @Test
    void decryptTriesConfigurationsSupportingTheHeaderFirst() throws Exception {
        List<String> attempts = new ArrayList<>();
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(List.of(
            new FailingEncryptionConfiguration("unsupported", false, attempts),
            new FailingEncryptionConfiguration("supported", true, attempts)));

        assertTrue(encryption.decrypt(EncryptedJWT.parse(nestedJwe(ENCRYPTION_SECRET))).isEmpty());
        assertEquals(List.of("supported", "unsupported"), attempts);
    }

    @Test
    void decryptDoesNotLogTokenControlledText() throws Exception {
        NimbusJsonWebTokenEncryption encryption = new NimbusJsonWebTokenEncryption(List.of(secretEncryption(ENCRYPTION_SECRET)));
        String header = Base64URL.encode("{\"alg\":\"x\\nFORGED\",\"enc\":\"A256GCM\"}").toString();
        EncryptedJWT jwt = EncryptedJWT.parse(header + "..AAAA.AAAA.AAAA");
        Logger logger = (Logger) LoggerFactory.getLogger(NimbusJsonWebTokenEncryption.class);
        Level original = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            logger.setLevel(Level.DEBUG);

            assertTrue(encryption.decrypt(jwt).isEmpty());
        } finally {
            logger.setLevel(original);
            logger.detachAppender(appender);
        }
        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("Decryption fails")), messages::toString);
        assertTrue(messages.stream().noneMatch(message -> message.contains("FORGED")), messages::toString);
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
