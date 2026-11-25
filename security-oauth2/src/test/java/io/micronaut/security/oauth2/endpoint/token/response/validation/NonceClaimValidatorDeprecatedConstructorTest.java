/*
 * Copyright 2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceFactory;
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A validator created with the deprecated no-argument constructor keeps the lenient validation, so its creation is
 * logged at WARN to make that visible.
 */
@ResourceLock("NonceClaimValidator-log")
class NonceClaimValidatorDeprecatedConstructorTest {
    private final Logger logger = (Logger) LoggerFactory.getLogger(NonceClaimValidator.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    void subclassWhichCallsTheDeprecatedConstructorIsReportedAtWarn() {
        NonceClaimValidator validator = new LenientNonceClaimValidator();

        List<ILoggingEvent> warnings = deprecatedConstructorWarnings();
        assertEquals(1, warnings.size());
        assertEquals(Level.WARN, warnings.getFirst().getLevel());
        assertTrue(warnings.getFirst().getFormattedMessage().startsWith(validator.getClass().getName() + " is created"));
    }

    @Test
    void validatorCreatedWithTheNonceFactoryIsNotReported() {
        new NonceClaimValidator(new DefaultNonceFactory(new NoNoncePersistence()));

        assertTrue(deprecatedConstructorWarnings().isEmpty());
    }

    private List<ILoggingEvent> deprecatedConstructorWarnings() {
        return appender.list.stream()
            .filter(event -> event.getFormattedMessage().contains("deprecated NonceClaimValidator() constructor"))
            .toList();
    }

    @SuppressWarnings("removal")
    private static final class LenientNonceClaimValidator extends NonceClaimValidator {
    }

    private static final class NoNoncePersistence implements NoncePersistence {
        @Override
        public Optional<String> retrieveNonce(HttpRequest<?> request) {
            return Optional.empty();
        }

        @Override
        public void persistNonce(HttpRequest<?> request, MutableHttpResponse response, String nonce) {
        }
    }
}
