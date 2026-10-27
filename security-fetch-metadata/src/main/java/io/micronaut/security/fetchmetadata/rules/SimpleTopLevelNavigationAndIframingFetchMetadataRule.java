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
import io.micronaut.http.Destination;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.Mode;
import io.micronaut.http.SecFetch;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SIMPLE_NAVIGATION;

/**
 * Allows simple {@code GET} navigations, including document and frame navigations, while
 * excluding requests whose destination is {@code object} or {@code embed}.
 */
@Requires(classes = HttpRequest.class)
@Requires(property = PROPERTY_ALLOW_SIMPLE_NAVIGATION, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
final class SimpleTopLevelNavigationAndIframingFetchMetadataRule implements HttpRequestFetchMetadataRule {
    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.SIMPLE_NAVIGATION;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        if (secFetch == null) {
            return FetchMetadataRuleResult.UNKNOWN;
        }
        if (secFetch.mode() == Mode.NAVIGATE &&
            request.getMethod() == HttpMethod.GET &&
            (secFetch.dest() != Destination.OBJECT && secFetch.dest() != Destination.EMBED)
        ) {
            return FetchMetadataRuleResult.ALLOWED;
        }
        return FetchMetadataRuleResult.UNKNOWN;
    }
}
