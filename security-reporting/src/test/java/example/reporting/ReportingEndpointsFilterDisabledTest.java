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
package example.reporting;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.reporting.ReportingEndpointConfiguration;
import io.micronaut.security.reporting.ReportingEndpoints;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;

@Property(name = "spec.name", value = ReportingEndpointsFilterDisabledTest.SPEC_NAME)
@Property(name = ReportingEndpointConfiguration.PREFIX + ".csp.url", value = "/csp/report")
@Property(name = "micronaut.security.reporting.filter.enabled", value = StringUtils.FALSE)
@MicronautTest
class ReportingEndpointsFilterDisabledTest {
    static final String SPEC_NAME = "ReportingEndpointsFilterDisabledTest";

    @Test
    void doesNotAddHeaderWhenFilterIsDisabled(@Client("/") HttpClient httpClient) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/reporting-disabled"));

        assertNull(response.header(ReportingEndpoints.HEADER_NAME));
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/reporting-disabled")
    static final class TestController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
