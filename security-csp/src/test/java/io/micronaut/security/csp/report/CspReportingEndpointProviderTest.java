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
package io.micronaut.security.csp.report;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.reporting.ReportingEndpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CspReportingEndpointProviderTest {

    @ParameterizedTest
    @ValueSource(strings = {"//other-host.example/x", "relative/path", "/csp report", "/csp\"report", "/csp\\report"})
    void rejectsAPathThatIsNotALocalAbsolutePath(String path) {
        ContentSecurityPolicyControllerConfigurationProperties controller = new ContentSecurityPolicyControllerConfigurationProperties();
        controller.setPath(path);

        assertThrows(ConfigurationException.class, () -> new CspReportingEndpointProvider(enabledReportTo(), controller, null));
    }

    @Test
    void advertisesALocalPath() {
        ContentSecurityPolicyControllerConfigurationProperties controller = new ContentSecurityPolicyControllerConfigurationProperties();
        controller.setPath("/reports/csp");

        ReportingEndpoint endpoint = new CspReportingEndpointProvider(enabledReportTo(), controller, null).reportingEndpoint(HttpRequest.GET("/"));

        assertNotNull(endpoint);
        assertEquals(URI.create("/reports/csp"), endpoint.getUrl());
    }

    @Test
    void advertisesNothingWhenReportToIsDisabled() {
        assertNull(new CspReportingEndpointProvider(new ReportToConfigurationProperties(),
            new ContentSecurityPolicyControllerConfigurationProperties(), null).reportingEndpoint(HttpRequest.GET("/")));
    }

    private static ReportToConfigurationProperties enabledReportTo() {
        ReportToConfigurationProperties reportTo = new ReportToConfigurationProperties();
        reportTo.setEnabled(true);
        return reportTo;
    }
}
