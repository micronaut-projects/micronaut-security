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
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "DefaultDirectiveDefaultsToTest")
@MicronautTest
class DefaultDirectiveDefaultsToTest {
    @Test
    void defaultSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).defaultSrc().isNone());
    }

    @Test
    void connectSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).connectSrc().isNone());
    }

    @Test
    void fontSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).fontSrc().isNone());
    }

    @Test
    void formActionDefaultsToSelf(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).formAction().isSelf());
    }

    @Test
    void frameAncestorsDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).frameAncestors().isNone());
    }

    @Test
    void frameSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).frameSrc().isNone());
    }

    @Test
    void imgSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).imgSrc().isNone());
    }

    @Test
    void manifestSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).manifestSrc().isNone());
    }

    @Test
    void mediaSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).mediaSrc().isNone());
    }

    @Test
    void prefetchSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).prefetchSrc().isNone());
    }

    @Test
    void reportUriIsNotIncludedByDefault(@Client("/") HttpClient httpClient) {
        assertNull(contentSecurityPolicy(httpClient).reportUri());
    }

    @Test
    void requireTrustedTypesForDefaultsToScript(@Client("/") HttpClient httpClient) {
        assertEquals("'script'", contentSecurityPolicy(httpClient).requireTrustedTypesFor().value());
    }

    @Test
    void styleSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).styleSrc().isNone());
    }

    @Test
    void workerSrcDefaultsToNone(@Client("/") HttpClient httpClient) {
        assertTrue(contentSecurityPolicy(httpClient).workerSrc().isNone());
    }

    private ContentSecurityPolicy contentSecurityPolicy(HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(HttpRequest.GET("/cspexample")));
        ContentSecurityPolicy csp = ContentSecurityPolicy.of(response);
        assertNotNull(csp);
        return csp;
    }

    @Requires(property = "spec.name", value = "DefaultDirectiveDefaultsToTest")
    @Controller("/cspexample")
    static class CspController {
        @Get
        @Status(HttpStatus.OK)
        void index() {
        }
    }
}
