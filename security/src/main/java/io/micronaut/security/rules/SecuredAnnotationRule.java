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

import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.inject.annotation.EvaluatedAnnotationValue;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteMatch;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Security rule implementation for the {@link Secured} annotation.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class SecuredAnnotationRule extends AbstractSecurityRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = ConfigurationInterceptUrlMapRule.ORDER - 100;

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
     *
     * @param request The current request
     * @param routeMatch The matched route
     * @param authentication The authentication, or null if none found
     * @return The result
     */
    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Authentication authentication) {
        if (routeMatch instanceof MethodBasedRouteMatch) {
            MethodBasedRouteMatch<?, ?> methodRoute = ((MethodBasedRouteMatch) routeMatch);
            if (methodRoute.hasAnnotation(Secured.class)) {

                AnnotationValue<Secured> securedAnnotation = methodRoute.getAnnotation(Secured.class);
                if (securedAnnotation instanceof EvaluatedAnnotationValue<Secured>) {

                    // this doesn't work right, because Secured value is String[], not String
//                    Optional<SecurityRuleResult> result = securedAnnotation.booleanValue()
//                        .map(b -> (Boolean.TRUE.equals(b) ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED));
//                    if (result.isPresent()) {
//                        return Mono.just(result.get());
//                    }

                    // I think we want something like this. It's not exactly right, but I'll fix,
                    // ...or we should consider adding to Secured: `String condition() default "";`
                    // then we can keep the above code using `securedAnnotation.booleanValue("cpndition")`
                    SecurityRuleResult result = Arrays.stream(securedAnnotation.stringValues())
                        .anyMatch(Boolean::valueOf) ? SecurityRuleResult.ALLOWED : SecurityRuleResult.REJECTED;
                        return Mono.just(result);
                }
                List<String> values = Arrays.asList(securedAnnotation.stringValues());
                if (values.contains(SecurityRule.DENY_ALL)) {
                    return Mono.just(SecurityRuleResult.REJECTED);
                }
                return compareRoles(values, getRoles(authentication));
            }
        }
        return Mono.just(SecurityRuleResult.UNKNOWN);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
