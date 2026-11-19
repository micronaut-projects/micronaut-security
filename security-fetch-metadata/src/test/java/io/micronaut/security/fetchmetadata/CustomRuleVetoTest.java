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
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * An application rule bean typed {@code FetchMetadataRule<HttpRequest<?>>} is picked up by the
 * filter, and its order lets it reject a request that a built-in rule would allow.
 */
@Property(name = "spec.name", value = "CustomRuleVetoTest")
@MicronautTest
class CustomRuleVetoTest {

    @Test
    void aCustomRuleRunningFirstCanRejectARequestABuiltInRuleWouldAllow(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/fetch-metadata")).getStatus());

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/fetch-metadata/filtered/test")));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    @Requires(property = "spec.name", value = "CustomRuleVetoTest")
    @Singleton
    static class RejectFilteredPathRule implements FetchMetadataRule<HttpRequest<?>> {
        @Override
        public FetchMetadataRuleResult check(HttpRequest<?> request) {
            return request.getPath().startsWith("/fetch-metadata/filtered")
                ? FetchMetadataRuleResult.REJECTED
                : FetchMetadataRuleResult.UNKNOWN;
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }
}
