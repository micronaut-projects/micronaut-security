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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RepositoryCsrfTokenValidatorLoggingTest {

    private static final String MALFORMED_TOKEN = "malformed-token-without-separator";
    private static final String WELL_FORMED_TOKEN = "hmac" + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR + "random";

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
        RepositoryCsrfTokenValidator<HttpRequest<?>> validator = validator(MALFORMED_TOKEN);

        assertFalse(validator.validateCsrfToken(request(), MALFORMED_TOKEN));

        List<ILoggingEvent> events = appender.list;
        assertEquals(1, events.size(), "expected exactly one log event for the rejection");
        ILoggingEvent event = events.get(0);
        assertFalse(event.getFormattedMessage().contains(MALFORMED_TOKEN),
                "CSRF token value must not be logged: " + event.getFormattedMessage());
        assertEquals(Level.WARN, event.getLevel(), "a malformed repository token is a misconfiguration and must be surfaced at WARN");
        assertEquals("CSRF token in repository is not in the expected hmac" + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR + "random format",
                event.getFormattedMessage());
    }

    @Test
    void wellFormedTokenMatchingRepositoryTokenIsValid() {
        RepositoryCsrfTokenValidator<HttpRequest<?>> validator = validator(WELL_FORMED_TOKEN);

        assertTrue(validator.validateCsrfToken(request(), WELL_FORMED_TOKEN));
        assertFalse(validator.validateCsrfToken(request(), "other" + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR + "random"));
        assertFalse(validator.validateCsrfToken(request(), MALFORMED_TOKEN));
        assertFalse(validator.validateCsrfToken(request(), null));

        for (ILoggingEvent event : appender.list) {
            assertFalse(event.getFormattedMessage().contains(WELL_FORMED_TOKEN),
                    "CSRF token value must not be logged: " + event.getFormattedMessage());
        }
    }

    private static HttpRequest<?> request() {
        return new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", "username=sherlock&password=123456");
    }

    private static RepositoryCsrfTokenValidator<HttpRequest<?>> validator(String tokenInRepository) {
        CsrfTokenRepository<HttpRequest<?>> repository = request -> Optional.of(tokenInRepository);
        CsrfHmacTokenGenerator<HttpRequest<?>> generator = new CsrfHmacTokenGenerator<>() {
            @Override
            public @NonNull String hmac(@NonNull HttpRequest<?> request, @NonNull String base64EncodedRandomValue) {
                return "hmac";
            }

            @Override
            public @NonNull String generateCsrfToken(HttpRequest<?> request) {
                return WELL_FORMED_TOKEN;
            }
        };
        return new RepositoryCsrfTokenValidator<>(List.of(repository), generator);
    }
}
