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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end check of the default policy: one application context serves the success and error
 * responses, which must all carry the same deny-by-default header.
 */
@Property(name = "spec.name", value = "DefaultPolicyHttpTest")
@MicronautTest
class DefaultPolicyHttpTest {
    static final String DEFAULT_POLICY = "base-uri 'none'; default-src 'none'; connect-src 'none'; font-src 'none'; "
        + "object-src 'none'; require-trusted-types-for 'script'; frame-ancestors 'none'; frame-src 'none'; img-src 'none'; "
        + "manifest-src 'none'; media-src 'none'; form-action 'self'; worker-src 'none'; style-src 'none'; script-src 'none'";

    @Test
    void successfulResponseCarriesTheDefaultPolicy(@Client("/") HttpClient httpClient) {
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/default-policy"), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(DEFAULT_POLICY, response.header(HttpHeaders.CONTENT_SECURITY_POLICY));
    }

    @Test
    void notFoundResponseCarriesTheDefaultPolicy(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/no-such-path"), String.class));

        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
        assertEquals(DEFAULT_POLICY, exception.getResponse().header(HttpHeaders.CONTENT_SECURITY_POLICY));
    }

    @Test
    void serverErrorResponseCarriesTheDefaultPolicy(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/default-policy/failure"), String.class));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, exception.getStatus());
        assertEquals(DEFAULT_POLICY, exception.getResponse().header(HttpHeaders.CONTENT_SECURITY_POLICY));
    }

    @Requires(property = "spec.name", value = "DefaultPolicyHttpTest")
    @Controller("/default-policy")
    static class DefaultPolicyController {
        @Get
        String index() {
            return "ok";
        }

        @Get("/failure")
        String failure() {
            throw new IllegalStateException("failure");
        }
    }
}
