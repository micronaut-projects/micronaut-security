package io.micronaut.security.token.jwt.generator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.util.Base64URL;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.token.jwt.generator.refresh-token.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest(startApplication = false)
class SignedRefreshTokenGeneratorLoggingTest {

    private static final String PAYLOAD = "test-fixture-not-a-secret";

    @Inject
    SignedRefreshTokenGenerator generator;

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(SignedRefreshTokenGenerator.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void validRefreshTokenIsAcceptedWithoutLogging() {
        Authentication authentication = Authentication.build("sherlock");
        String key = generator.createKey(authentication);
        Optional<String> refreshToken = generator.generate(authentication, key);
        assertTrue(refreshToken.isPresent());

        Optional<String> validated = generator.validate(refreshToken.get());

        assertTrue(validated.isPresent());
        assertEquals(key, validated.get());
        assertTrue(appender.list.isEmpty());
    }

    @Test
    void tamperedRefreshTokenIsRejectedWithoutLogging() {
        Authentication authentication = Authentication.build("sherlock");
        String refreshToken = generator.generate(authentication, generator.createKey(authentication)).get();
        String tampered = flipSignatureBit(refreshToken);

        assertFalse(generator.validate(tampered).isPresent());
        assertNotLogged(tampered);
    }

    @Test
    void encryptedAccessTokenIsRejectedAndNeverLogged() {
        // A JWE compact serialization has five parts and cannot be parsed as a JWS object
        String jwe = String.join(".",
                base64Url("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A128GCM\"}"),
                base64Url("encrypted-key-" + PAYLOAD),
                base64Url("iv"),
                base64Url("ciphertext-" + PAYLOAD),
                base64Url("tag"));

        assertFalse(generator.validate(jwe).isPresent());
        assertNotLogged(jwe);
        assertNotLogged(PAYLOAD);
    }

    @Test
    void asymmetricallySignedAccessTokenIsRejectedAndNeverLogged() {
        // An RS256-signed token parses as a JWS object but the HMAC verifier does not support its algorithm
        String jws = String.join(".",
                base64Url("{\"alg\":\"RS256\"}"),
                base64Url("{\"sub\":\"sherlock\",\"secret\":\"" + PAYLOAD + "\"}"),
                base64Url("signature"));

        assertFalse(generator.validate(jws).isPresent());
        assertNotLogged(jws);
        assertNotLogged(PAYLOAD);
    }

    @Test
    void malformedTokenIsRejectedAndNeverLogged() {
        String bogus = "bogus-" + PAYLOAD;

        assertFalse(generator.validate(bogus).isPresent());
        assertNotLogged(bogus);
    }

    private void assertNotLogged(String value) {
        List<String> messages = appender.list.stream()
                .map(event -> event.getThrowableProxy() == null
                        ? event.getFormattedMessage()
                        : event.getFormattedMessage() + " " + event.getThrowableProxy().getMessage())
                .collect(Collectors.toList());
        assertTrue(messages.stream().noneMatch(message -> message.contains(value)), () -> value + " was logged: " + messages);
    }

    private static String flipSignatureBit(String jws) {
        int signatureStart = jws.lastIndexOf('.') + 1;
        byte[] signature = new Base64URL(jws.substring(signatureStart)).decode();
        signature[0] ^= 0x01;
        return jws.substring(0, signatureStart) + Base64URL.encode(signature);
    }

    private static String base64Url(String value) {
        return Base64URL.encode(value.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
