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
import io.micronaut.security.fetchmetadata.DenyCrossSiteNavigation;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import io.micronaut.web.router.RouteAttributes;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SIMPLE_NAVIGATION;

/**
 * Allows simple {@code GET} navigations, including document and frame navigations, while
 * excluding requests whose destination is {@code object} or {@code embed} or is not recognized.
 *
 * <p>Unless {@link FetchMetadataRulesConfiguration#isDenyAnnotatedCrossSiteNavigation()} is
 * disabled, navigations to a route annotated with {@link DenyCrossSiteNavigation} are not
 * allowed by this rule, so that they are rejected unless another rule allows them.</p>
 */
@Requires(property = PROPERTY_ALLOW_SIMPLE_NAVIGATION, value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
final class SimpleTopLevelNavigationAndIframingFetchMetadataRule implements HttpRequestFetchMetadataRule {

    private static final Logger LOG = LoggerFactory.getLogger(SimpleTopLevelNavigationAndIframingFetchMetadataRule.class);
    private static final String GUIDE_URL =
        "https://micronaut-projects.github.io/micronaut-security/latest/guide/#fetchMetadataSensitiveNavigationRoutes";

    private final boolean denyAnnotatedCrossSiteNavigation;

    /**
     * @param configuration the built-in rules configuration
     */
    SimpleTopLevelNavigationAndIframingFetchMetadataRule(FetchMetadataRulesConfiguration configuration) {
        this.denyAnnotatedCrossSiteNavigation = configuration.isDenyAnnotatedCrossSiteNavigation();
    }

    @Override
    public int getOrder() {
        return FetchMetadataRuleOrder.SIMPLE_NAVIGATION;
    }

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        if (secFetch == null) {
            return FetchMetadataRuleResult.UNKNOWN;
        }
        Destination destination = secFetch.dest();
        if (secFetch.mode() != Mode.NAVIGATE ||
            request.getMethod() != HttpMethod.GET ||
            destination == null ||
            destination == Destination.OBJECT ||
            destination == Destination.EMBED
        ) {
            return FetchMetadataRuleResult.UNKNOWN;
        }
        if (denyAnnotatedCrossSiteNavigation && targetsRouteDenyingCrossSiteNavigation(request)) {
            if (LOG.isDebugEnabled()) {
                // the filter logs the path, sanitized, when no later rule allows the request
                LOG.debug("navigation with Sec-Fetch-Site [{}] targets a route annotated with @DenyCrossSiteNavigation, so the simple "
                    + "navigation rule does not allow it. Set {}=false to allow such navigations. See {}",
                    secFetch.site(), FetchMetadataRulesConfiguration.PROPERTY_DENY_ANNOTATED_CROSS_SITE_NAVIGATION, GUIDE_URL);
            }
            return FetchMetadataRuleResult.UNKNOWN;
        }
        return FetchMetadataRuleResult.ALLOWED;
    }

    // RouteAttributes comes from micronaut-router, which every HTTP server that runs the filter
    // brings along, so no @Requires guard: with one, a missing router would remove this rule.
    private static boolean targetsRouteDenyingCrossSiteNavigation(HttpRequest<?> request) {
        return RouteAttributes.getRouteMatch(request)
            .filter(routeMatch -> routeMatch.getAnnotationMetadata().hasAnnotation(DenyCrossSiteNavigation.class))
            .isPresent();
    }
}
