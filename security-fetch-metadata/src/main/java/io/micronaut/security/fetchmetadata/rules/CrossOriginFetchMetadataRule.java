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
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.http.server.cors.CorsOriginConfiguration;
import io.micronaut.http.server.cors.CrossOriginUtil;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_CROSS_ORIGIN;

/**
 * Allows a cross-origin request when its matched route declares a CORS configuration that
 * permits the request origin and HTTP method.
 *
 * <p>Merely targeting a route annotated with
 * {@link io.micronaut.http.server.cors.CrossOrigin CrossOrigin} is insufficient. The request
 * must include an {@code Origin} header accepted by that route's CORS configuration. This keeps
 * the Fetch Metadata exemption aligned with the validation performed by Micronaut's CORS
 * filter.</p>
 */
@Requires(classes = HttpRequest.class)
@Requires(property = PROPERTY_ALLOW_CROSS_ORIGIN, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
final class CrossOriginFetchMetadataRule implements HttpRequestFetchMetadataRule {

    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.CROSS_ORIGIN;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        String origin = request.getOrigin().orElse(null);
        if (origin == null) {
            return FetchMetadataRuleResult.UNKNOWN;
        }
        Optional<CorsOriginConfiguration> originConfiguration =
            CrossOriginUtil.getCorsOriginConfigurationForRequest(request);
        if (originConfiguration
            .filter(configuration -> matchesOrigin(configuration, origin))
            .filter(configuration -> matchesMethod(configuration, request.getMethod()))
            .isPresent()) {
            return FetchMetadataRuleResult.ALLOWED;
        }
        return FetchMetadataRuleResult.UNKNOWN;
    }

    static boolean matchesOrigin(CorsOriginConfiguration configuration, String origin) {
        if (configuration.getAllowedOriginsRegex()
            .map(regex -> Pattern.matches(regex, origin))
            .orElse(false)) {
            return true;
        }
        List<String> allowedOrigins = configuration.getAllowedOrigins();
        return !allowedOrigins.isEmpty() &&
            ((configuration.getAllowedOriginsRegex().isEmpty() &&
                Objects.equals(allowedOrigins, CorsOriginConfiguration.ANY)) ||
                allowedOrigins.contains(origin));
    }

    static boolean matchesMethod(CorsOriginConfiguration configuration, HttpMethod method) {
        List<HttpMethod> allowedMethods = configuration.getAllowedMethods();
        return Objects.equals(allowedMethods, CorsOriginConfiguration.ANY_METHOD) ||
            allowedMethods.contains(method);
    }
}
