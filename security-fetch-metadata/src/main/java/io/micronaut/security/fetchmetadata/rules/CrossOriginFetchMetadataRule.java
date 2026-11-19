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
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.http.server.cors.CorsOriginConfiguration;
import io.micronaut.http.server.cors.CorsUtil;
import io.micronaut.http.server.cors.CrossOriginUtil;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration.PROPERTY_ALLOW_CROSS_ORIGIN;
import static io.micronaut.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD;

/**
 * Allows a cross-origin request when its matched route declares a CORS configuration that
 * permits the request origin and HTTP method.
 *
 * <p>Merely targeting a route annotated with
 * {@link io.micronaut.http.server.cors.CrossOrigin CrossOrigin} is insufficient. The request
 * must include an {@code Origin} header accepted by that route's CORS configuration. This keeps
 * the Fetch Metadata exemption aligned with the validation performed by Micronaut's CORS
 * filter. For a preflight request, the requested method is read from the
 * {@code Access-Control-Request-Method} header.</p>
 *
 * <p>When the route's CORS configuration does not allow credentials, a request that carries a
 * {@code Cookie} header is not exempted. Browsers send cookies on simple cross-origin requests
 * (for example a {@code no-cors} fetch or a form submission) even though CORS keeps the response
 * from being read, so exempting them would let a cross-site page make credentialed requests the
 * route declared it does not accept.</p>
 */
@Requires(classes = { CorsOriginConfiguration.class, CorsUtil.class, CrossOriginUtil.class })
@Requires(property = PROPERTY_ALLOW_CROSS_ORIGIN, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
final class CrossOriginFetchMetadataRule implements HttpRequestFetchMetadataRule {

    private static final Logger LOG = LoggerFactory.getLogger(CrossOriginFetchMetadataRule.class);

    private final Map<String, Optional<Pattern>> allowedOriginsPatterns = new ConcurrentHashMap<>();

    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.CROSS_ORIGIN;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        String origin = request.getOrigin().orElse(null);
        if (!StringUtils.hasText(origin)) {
            return FetchMetadataRuleResult.UNKNOWN;
        }
        Optional<CorsOriginConfiguration> originConfiguration =
            CrossOriginUtil.getCorsOriginConfigurationForRequest(request);
        if (originConfiguration
            .filter(configuration -> matchesOrigin(configuration, origin))
            .filter(configuration -> matchesMethod(configuration, request))
            .filter(configuration -> matchesCredentials(configuration, request))
            .isPresent()) {
            return FetchMetadataRuleResult.ALLOWED;
        }
        return FetchMetadataRuleResult.UNKNOWN;
    }

    boolean matchesOrigin(CorsOriginConfiguration configuration, String origin) {
        if (configuration.getAllowedOriginsRegex()
            .flatMap(regex -> allowedOriginsPatterns.computeIfAbsent(regex, CrossOriginFetchMetadataRule::compile))
            .map(pattern -> pattern.matcher(origin).matches())
            .orElse(false)) {
            return true;
        }
        List<String> allowedOrigins = configuration.getAllowedOrigins();
        return !allowedOrigins.isEmpty() &&
            ((configuration.getAllowedOriginsRegex().isEmpty() &&
                Objects.equals(allowedOrigins, CorsOriginConfiguration.ANY)) ||
                allowedOrigins.contains(origin));
    }

    /**
     * Compiles an allowed origins regular expression. An invalid expression matches no origin, so
     * that it denies the exemption instead of failing the request.
     *
     * @param regex the allowed origins regular expression
     * @return the compiled pattern, or empty when the expression is invalid
     */
    private static Optional<Pattern> compile(String regex) {
        try {
            return Optional.of(Pattern.compile(regex));
        } catch (PatternSyntaxException e) {
            LOG.warn("Invalid @CrossOrigin allowed origins regular expression [{}]; it matches no origin for Fetch Metadata", regex, e);
            return Optional.empty();
        }
    }

    static boolean matchesMethod(CorsOriginConfiguration configuration, HttpRequest<?> request) {
        HttpMethod requestMethod = request.getMethod();
        HttpMethod methodToMatch = CorsUtil.isPreflightRequest(request)
            ? request.getHeaders().getFirst(ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.class).orElse(requestMethod)
            : requestMethod;
        List<HttpMethod> allowedMethods = configuration.getAllowedMethods();
        return Objects.equals(allowedMethods, CorsOriginConfiguration.ANY_METHOD) ||
            allowedMethods.contains(methodToMatch);
    }

    static boolean matchesCredentials(CorsOriginConfiguration configuration, HttpRequest<?> request) {
        return configuration.isAllowCredentials() || !request.getHeaders().contains(HttpHeaders.COOKIE);
    }
}
