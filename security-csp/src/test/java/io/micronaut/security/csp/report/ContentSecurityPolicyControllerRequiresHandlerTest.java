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

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.csp.conf.reportTo.ReportToConfigurationProperties;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.security.reporting.ReportingEndpoints;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = ReportToConfigurationProperties.PREFIX + ".enabled", value = "true")
@MicronautTest
class ContentSecurityPolicyControllerRequiresHandlerTest {

    @Test
    void reportingEndpointIsNotRegisteredWithoutAHandler(@Client("/") HttpClient httpClient) {
        HttpRequest<byte[]> request = HttpRequest.POST(ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH,
                "[]".getBytes(StandardCharsets.UTF_8))
            .contentType(MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON));
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request));

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
        assertNull(exception.getResponse().header(ReportingEndpoints.HEADER_NAME));
    }
}
