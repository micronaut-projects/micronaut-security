package io.micronaut.security.csrf.validator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.csrf.generator.CsrfHmacTokenGenerator;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RepositoryCsrfTokenValidatorLoggingTest {

    private static final String MALFORMED_TOKEN = "malformed-token-without-separator";

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;
    private Level originalLevel;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(RepositoryCsrfTokenValidator.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void malformedTokenMatchingRepositoryTokenIsNotLogged() {
        CsrfTokenRepository<HttpRequest<?>> repository = request -> Optional.of(MALFORMED_TOKEN);
        CsrfHmacTokenGenerator<HttpRequest<?>> generator = new CsrfHmacTokenGenerator<>() {
            @Override
            public String hmac(HttpRequest<?> request, String base64EncodedRandomValue) {
                return "hmac";
            }

            @Override
            public String generateCsrfToken(HttpRequest<?> request) {
                return "hmac" + HMAC_RANDOM_SEPARATOR + "random";
            }
        };
        RepositoryCsrfTokenValidator<HttpRequest<?>> validator = new RepositoryCsrfTokenValidator<>(List.of(repository), generator);
        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", "username=sherlock&password=123456");

        assertFalse(validator.validateCsrfToken(request, MALFORMED_TOKEN));

        List<ILoggingEvent> events = appender.list;
        assertFalse(events.isEmpty(), "expected the rejection to be logged");
        for (ILoggingEvent event : events) {
            assertFalse(event.getFormattedMessage().contains(MALFORMED_TOKEN),
                    "CSRF token value must not be logged: " + event.getFormattedMessage());
            assertTrue(event.getLevel().toInt() < Level.WARN.toInt(),
                    "CSRF token rejection must not be logged at WARN or above: " + event.getLevel());
        }
    }
}
