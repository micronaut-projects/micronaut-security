/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.csp.filters;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.event.StartupEvent;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyHeaderUnavailableWarningTest {

    @Test
    void isNotActiveWhenTheHttpServerProvidesResponseHeaderPopulator() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertFalse(context.containsBean(ContentSecurityPolicyHeaderUnavailableWarning.class));
            assertTrue(context.containsBean(ContentSecurityPolicyStartupLogger.class));
        }
    }

    @Test
    void warnsThatNoHeaderIsSent() {
        Logger logger = (Logger) LoggerFactory.getLogger(ContentSecurityPolicyHeaderUnavailableWarning.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try (ApplicationContext context = ApplicationContext.builder().build()) {
            new ContentSecurityPolicyHeaderUnavailableWarning().onApplicationEvent(new StartupEvent(context));
        } finally {
            logger.detachAppender(appender);
        }

        assertEquals(1, appender.list.size());
        assertTrue(appender.list.get(0).getFormattedMessage().endsWith("No CSP header is sent."));
    }
}
