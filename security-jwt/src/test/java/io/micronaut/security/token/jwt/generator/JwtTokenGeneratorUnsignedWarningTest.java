package io.micronaut.security.token.jwt.generator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenGeneratorUnsignedWarningTest {

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(JwtTokenGenerator.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.WARN);
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
    void warnsWhenNoGeneratorSignatureConfigurationIsPresent() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertNull(context.getBean(JwtTokenGenerator.class).getSignatureConfiguration());
        }

        List<String> warnings = warnings();
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("JwtTokenGenerator will emit unsigned JWTs (alg=none)"));
        assertTrue(warnings.get(0).contains("unless micronaut.security.token.jwt.accept-unsigned-tokens is true"));
    }

    @Test
    void doesNotWarnWhenGeneratorSignatureConfigurationIsPresent() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne"))) {
            assertNotNull(context.getBean(JwtTokenGenerator.class).getSignatureConfiguration());
        }

        assertTrue(warnings().isEmpty());
    }

    private List<String> warnings() {
        return appender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }
}
