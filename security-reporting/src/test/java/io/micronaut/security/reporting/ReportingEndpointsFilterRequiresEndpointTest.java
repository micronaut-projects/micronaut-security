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

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = ReportingEndpointsFilterRequiresEndpointTest.SPEC_NAME)
@MicronautTest
class ReportingEndpointsFilterRequiresEndpointTest {
    static final String SPEC_NAME = "ReportingEndpointsFilterRequiresEndpointTest";

    @Inject
    BeanContext beanContext;

    @Test
    void doesNotAddAnEmptyHeaderWithoutEndpoints(@Client("/") HttpClient httpClient) {
        HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/without-reporting-endpoints"));

        assertNull(response.header(ReportingEndpoints.HEADER_NAME));
        assertTrue(beanContext.findBean(ReportingEndpointsFilter.class).isEmpty());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/without-reporting-endpoints")
    static final class TestController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
            // No response body is required; the test only verifies conditional filter loading.
        }
    }
}
