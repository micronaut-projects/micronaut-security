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
package io.micronaut.security.reporting;

import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportingEndpointUtilsTest {
    private static final URI URL = URI.create("/csp/report");

    @Test
    void acceptsAnEndpointWithAValidNameAndAUrl() {
        assertTrue(ReportingEndpointUtils.isValid(endpoint("csp", URL)));
        assertTrue(ReportingEndpointUtils.isValid(endpoint("csp", URI.create("https://reports.example.com/csp"))));
    }

    @Test
    void rejectsANullEndpoint() {
        assertFalse(ReportingEndpointUtils.isValid(null));
    }

    @Test
    void rejectsAnInvalidOrMissingName() {
        assertFalse(ReportingEndpointUtils.isValid(endpoint("Csp", URL)));
        assertFalse(ReportingEndpointUtils.isValid(endpoint("", URL)));
        assertFalse(ReportingEndpointUtils.isValid(endpoint(null, URL)));
    }

    @Test
    void rejectsAMissingOrEmptyUrl() {
        assertFalse(ReportingEndpointUtils.isValid(endpoint("csp", null)));
        assertFalse(ReportingEndpointUtils.isValid(endpoint("csp", URI.create(""))));
    }

    @Test
    void requireRejectsAnInvalidNameBeforeAMissingUrl() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> ReportingEndpointUtils.require("Csp", null));

        assertTrue(e.getMessage().contains(ReportingEndpointUtils.KEY_GRAMMAR), e.getMessage());
    }

    @Test
    void requireAcceptsAValidNameAndUrl() {
        assertDoesNotThrow(() -> ReportingEndpointUtils.require("csp", URL));
    }

    @SuppressWarnings("NullAway")
    private static ReportingEndpoint endpoint(@Nullable String name, @Nullable URI url) {
        return new ReportingEndpoint() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public URI getUrl() {
                return url;
            }
        };
    }
}
