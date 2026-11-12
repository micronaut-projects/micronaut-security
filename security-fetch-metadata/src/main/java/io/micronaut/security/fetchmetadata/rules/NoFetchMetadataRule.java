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
package io.micronaut.security.fetchmetadata.rules;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration.PROPERTY_ALLOW_NO_FETCH_METADATA;

/**
 * Allows clients that do not send the {@code Sec-Fetch-Site} header.
 * This compatibility rule must be used together with other request-forgery protections.
 */
@Requires(classes = HttpRequest.class)
@Requires(property = PROPERTY_ALLOW_NO_FETCH_METADATA, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
@Internal
final class NoFetchMetadataRule implements HttpRequestFetchMetadataRule {
    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.NO_FETCH_METADATA;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        if (!request.getHeaders().contains(HttpHeaders.SEC_FETCH_SITE)) {
            return FetchMetadataRuleResult.ALLOWED;
        }
        return FetchMetadataRuleResult.UNKNOWN;
    }
}
