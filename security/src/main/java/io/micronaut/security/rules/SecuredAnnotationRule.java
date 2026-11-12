/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.rules;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.web.router.RouteAttributes;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.annotation.EvaluatedAnnotationValue;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import jakarta.inject.Singleton;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * Security rule implementation for the {@link Secured} annotation.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Requires(classes = { HttpRequest.class })
@Singleton
public class SecuredAnnotationRule extends AbstractSecurityRule<HttpRequest<?>> {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = ConfigurationInterceptUrlMapRule.ORDER - 100;

    private static final Logger LOG = LoggerFactory.getLogger(SecuredAnnotationRule.class);

    /**
     *
     * @param rolesFinder Roles Parser
     */
    public SecuredAnnotationRule(RolesFinder rolesFinder) {
        super(rolesFinder);
    }

    /**
     * Returns {@link SecurityRuleResult#UNKNOWN} if the {@link Secured} annotation is not
     * found on the method or class, or if the route match is not method based.
     * <p>
     * If the {@link Secured} value is an expression, the request is allowed only when the expression evaluates to
     * {@code true}. An expression that evaluates to {@code null}, for example one that navigates the user with
     * {@code user?.} for an anonymous request, rejects the request instead of deferring to later rules.
     *
     * @param request The current request
     * @param authentication The authentication, or null if none found
     * @return The result
     */
    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable Authentication authentication) {
        try (RouteMatch<?> routeMatch = RouteAttributes.getRouteMatch(request).orElse(null)) {
            if (routeMatch instanceof MethodBasedRouteMatch) {
                MethodBasedRouteMatch<?, ?> methodRoute = ((MethodBasedRouteMatch) routeMatch);
                AnnotationValue<Secured> securedAnnotation = methodRoute.getAnnotation(Secured.class);
                if (securedAnnotation != null) {
                    if (securedAnnotation instanceof EvaluatedAnnotationValue<Secured>) {
                        boolean[] arr = securedAnnotation.booleanValues();
                        if (arr.length == 0) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("@Secured expression for route [{} {}] did not evaluate to a boolean. Rejecting the request", request.getMethodName(), request.getPath());
                            }
                            return Mono.just(SecurityRuleResult.REJECTED);
                        }
                        return Mono.just(arr[0] ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED);
                    }
                    Optional<String[]> optionalValue = methodRoute.getValue(Secured.class, String[].class);
                    if (optionalValue.isPresent()) {
                        List<String> values = Arrays.asList(optionalValue.get());
                        if (values.contains(SecurityRule.DENY_ALL)) {
                            return Mono.just(SecurityRuleResult.REJECTED);
                        }
                        return compareRoles(values, getRoles(authentication));
                    }
                }
            }
        }
        return Mono.just(SecurityRuleResult.UNKNOWN);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
