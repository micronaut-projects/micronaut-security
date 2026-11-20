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
 * Server filter patterns use Ant matching, which does not treat a trailing slash as optional,
 * whereas the router does. The guide therefore recommends patterns ending in {@code /**}; this
 * test pins the behaviour that recommendation is based on.
 */
@Property(name = FetchMetadataFilterConfiguration.PROPERTY_PATTERN,
    value = "/fetch-metadata/filtered/test")
@Property(name = FetchMetadataRulesConfiguration.PROPERTY_ALLOW_NO_FETCH_METADATA,
    value = StringUtils.FALSE)
@MicronautTest
class FetchMetadataFilterExactPatternTest {
    @Test
    void anExactPatternDoesNotFilterTheTrailingSlashFormTheRouterStillMatches(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/fetch-metadata/filtered/test")));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/fetch-metadata/filtered/test/")).getStatus());
    }
}
