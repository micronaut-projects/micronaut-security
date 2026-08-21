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
import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.http.Site;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_SAME_ORIGIN;

/**
 * Allows requests whose Fetch Metadata identifies their initiator as the same origin.
 */
@Requires(classes = HttpRequest.class)
@Requires(property = PROPERTY_ALLOW_SAME_ORIGIN, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
@Internal
final class SameOriginFetchMetadataRule implements HttpRequestFetchMetadataRule {
    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.SAME_ORIGIN;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        if (secFetch != null && secFetch.site() == Site.SAME_ORIGIN) {
            return FetchMetadataRuleResult.ALLOWED;
        }
        return FetchMetadataRuleResult.UNKNOWN;
    }
}
