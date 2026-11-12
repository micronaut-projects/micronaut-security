package io.micronaut.security.token.reader;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.BasicAuthUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialLoggingTest {

    private static final String SECRET = "dXNlcjp0ZXN0LWZpeHR1cmUtbm90LWEtc2VjcmV0";

    private final List<Logger> loggers = List.of(
            (Logger) LoggerFactory.getLogger(HttpHeaderTokenReader.class),
            (Logger) LoggerFactory.getLogger(BasicAuthUtils.class));
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        appender = new ListAppender<>();
        appender.start();
        for (Logger logger : loggers) {
            logger.setLevel(Level.TRACE);
            logger.addAppender(appender);
        }
    }

    @AfterEach
    void cleanup() {
        for (Logger logger : loggers) {
            logger.detachAppender(appender);
            logger.setLevel(null);
        }
        appender.stop();
    }

    @Test
    void basicAuthorizationHeaderIsNotLoggedByReader() {
        HttpHeaderTokenReader reader = bearerReader();
        Optional<String> token = reader.findToken(HttpRequest.GET("/").header("Authorization", "Basic " + SECRET));
        assertTrue(token.isEmpty());
        assertNotLogged(SECRET);
    }

    @Test
    void bearerTokenIsStillExtracted() {
        HttpHeaderTokenReader reader = bearerReader();
        assertEquals(Optional.of("abc"), reader.findToken(HttpRequest.GET("/").header("Authorization", "Bearer abc")));
    }

    @Test
    void undecodableBasicCredentialsAreNotLogged() {
        String invalid = "not-base64!" + SECRET;
        assertTrue(BasicAuthUtils.parseCredentials("Basic " + invalid).isEmpty());
        assertNotLogged(invalid);
        assertNotLogged(SECRET);
    }

    private static HttpHeaderTokenReader bearerReader() {
        return new HttpHeaderTokenReader() {
            @Override
            protected String getPrefix() {
                return "Bearer";
            }

            @Override
            protected String getHeaderName() {
                return "Authorization";
            }
        };
    }

    private void assertNotLogged(String value) {
        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().noneMatch(m -> m.contains(value)), () -> value + " was logged: " + messages);
    }
}
