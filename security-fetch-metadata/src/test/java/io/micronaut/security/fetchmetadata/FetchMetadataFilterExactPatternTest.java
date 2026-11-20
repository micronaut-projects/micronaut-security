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
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The router treats a trailing slash as optional, and server filters match the path the router
 * uses. An exact filter pattern must therefore also filter the trailing slash form of the path;
 * otherwise that request would reach the route without being evaluated.
 */
@Property(name = FetchMetadataFilterConfiguration.PROPERTY_PATTERN,
    value = "/fetch-metadata/filtered/test")
@Property(name = FetchMetadataRulesConfiguration.PROPERTY_ALLOW_NO_FETCH_METADATA,
    value = StringUtils.FALSE)
@MicronautTest
class FetchMetadataFilterExactPatternTest {
    @Test
    void anExactPatternAlsoFiltersTheTrailingSlashFormTheRouterMatches(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertForbidden(client, "/fetch-metadata/filtered/test");
        assertForbidden(client, "/fetch-metadata/filtered/test/");
    }

    private static void assertForbidden(BlockingHttpClient client, String path) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET(path)));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }
}
