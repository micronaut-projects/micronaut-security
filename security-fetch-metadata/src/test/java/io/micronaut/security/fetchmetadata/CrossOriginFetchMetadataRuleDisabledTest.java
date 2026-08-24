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
import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.Mode;
import io.micronaut.http.Site;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfigurationProperties;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_NO_FETCH_METADATA,
    value = StringUtils.FALSE)
@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_CROSS_ORIGIN,
    value = StringUtils.FALSE)
@MicronautTest
class CrossOriginFetchMetadataRuleDisabledTest {

    @Test
    void disablingCrossOriginRuleRejectsOtherwisePermittedCorsRequest(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.GET("/fetch-metadata/cors")
            .header(HttpHeaders.SEC_FETCH_SITE, Site.CROSS_SITE.toString())
            .header(HttpHeaders.SEC_FETCH_MODE, Mode.CORS.toString())
            .header(HttpHeaders.SEC_FETCH_DEST, Destination.EMPTY.toString())
            .header(HttpHeaders.ORIGIN, "https://allowed.example");

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request));

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }
}
