/*
 * Copyright 2026 original authors
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

import io.micronaut.core.annotation.AnnotationMetadata;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Head;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.InterceptUrlMapPattern;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.web.router.RouteMatch;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.lang.annotation.Annotation;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The router answers a HEAD request with the {@code @Get} method of the same URI through an implicit HEAD route
 * unless a {@code @Head} method is declared, so an intercept URL map entry restricted to GET must also apply to
 * such HEAD requests unless an entry restricted to HEAD matches. A HEAD request answered by an explicitly declared
 * {@code @Head} method keeps the policy of the entries without a method.
 */
class InterceptUrlMapRuleHeadRequestTest {

    @Test
    void headRequestIsSubjectToTheGetEntryWhenItIsStricterThanTheMethodLessEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.GET),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.GET("/admin/secret"), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        // a HEAD request without a route, as for @Get(headRoute = false), is subject to the GET entry as well
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.HEAD("/admin/secret"), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/admin/secret"), Authentication.build("john")));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), Authentication.build("john")));
    }

    @Test
    void headRequestIsSubjectToTheRolesOfTheGetEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList("ROLE_ADMIN"), HttpMethod.GET),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), null));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), Authentication.build("john", Collections.singletonList("ROLE_USER"))));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), Authentication.build("john", Collections.singletonList("ROLE_ADMIN"))));
    }

    @Test
    void headRequestIsSubjectToTheGetEntryWhenItIsMorePermissiveThanTheMethodLessEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/v1/myResource/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.GET),
            new InterceptUrlMapPattern("/v1/myResource/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), null));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/v1/myResource/1"), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/v1/myResource/1")), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, routed(HttpRequest.POST("/v1/myResource/1", "body")), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, routed(HttpRequest.OPTIONS("/v1/myResource/1")), null));
    }

    @Test
    void entryRestrictedToHeadTakesPrecedenceOverTheGetEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.GET),
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.HEAD),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), null));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.GET("/admin/secret"), null));
    }

    @Test
    void headEntryDeclaredAfterTheGetEntryStillTakesPrecedence() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.GET),
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.HEAD));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/admin/secret"), null));
    }

    @Test
    void headRequestFallsBackToTheMethodLessEntryWhenNoGetEntryMatches() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.POST),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, routed(HttpRequest.POST("/admin/secret", "body")), null));
    }

    @Test
    void getEntryDoesNotApplyToOtherMethods() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.GET));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/admin/secret"), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, routed(HttpRequest.OPTIONS("/admin/secret")), null));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, routed(HttpRequest.POST("/admin/secret", "body")), null));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, routed(HttpRequest.DELETE("/admin/secret")), null));
    }

    @Test
    void unroutedRequestsOfAnyMethodAreSubjectToTheGetEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/assets/protected.txt", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.GET),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.POST("/assets/protected.txt", "body"), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.PUT("/assets/protected.txt", "body"), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.DELETE("/assets/protected.txt"), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.OPTIONS("/assets/protected.txt"), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.POST("/assets/protected.txt", "body"), Authentication.build("john")));
        // a routed POST is not subject to the GET entry
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, routed(HttpRequest.POST("/assets/protected.txt", "body")), null));
    }

    @Test
    void unroutedRequestPrefersTheEntryRestrictedToItsOwnMethod() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/assets/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.GET),
            new InterceptUrlMapPattern("/assets/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.POST));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.POST("/assets/a.txt", "body"), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, HttpRequest.PUT("/assets/a.txt", "body"), null));
    }

    @Test
    void explicitHeadRouteKeepsThePolicyOfTheMethodLessEntry() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/reports/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), HttpMethod.GET),
            new InterceptUrlMapPattern("/reports/**", Collections.singletonList("ROLE_ADMIN"), null));

        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.GET("/reports/status"), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, implicitHead(HttpRequest.HEAD("/reports/status")), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpRequest.HEAD("/reports/status"), null));
        // a @Head method is a handler of its own: a public GET policy does not make it public
        assertEquals(SecurityRuleResult.REJECTED, check(rule, explicitHead(HttpRequest.HEAD("/reports/status")), null));
        assertEquals(SecurityRuleResult.REJECTED, check(rule, explicitHead(HttpRequest.HEAD("/reports/status")), Authentication.build("john", Collections.singletonList("ROLE_USER"))));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, explicitHead(HttpRequest.HEAD("/reports/status")), Authentication.build("john", Collections.singletonList("ROLE_ADMIN"))));
    }

    @Test
    void explicitHeadRouteIsNotSubjectToAStricterGetEntryEither() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.GET),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, implicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, explicitHead(HttpRequest.HEAD("/admin/secret")), null));
    }

    @Test
    void entryRestrictedToHeadAppliesToExplicitHeadRoutes() {
        SecurityRule rule = rule(
            new InterceptUrlMapPattern("/admin/**", Collections.singletonList(SecurityRule.IS_AUTHENTICATED), HttpMethod.HEAD),
            new InterceptUrlMapPattern("/**", Collections.singletonList(SecurityRule.IS_ANONYMOUS), null));

        assertEquals(SecurityRuleResult.REJECTED, check(rule, explicitHead(HttpRequest.HEAD("/admin/secret")), null));
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, explicitHead(HttpRequest.HEAD("/admin/secret")), Authentication.build("john")));
    }

    private static RoutedRequest implicitHead(HttpRequest<?> request) {
        return new RoutedRequest(request, routeMatch(Get.class));
    }

    private static RoutedRequest explicitHead(HttpRequest<?> request) {
        return new RoutedRequest(request, routeMatch(Head.class));
    }

    private static RoutedRequest routed(HttpRequest<?> request) {
        return new RoutedRequest(request, routeMatch());
    }

    /**
     * @param annotations The annotations of the method the route targets
     * @return A route match which only answers its annotation metadata
     */
    @SafeVarargs
    private static RouteMatch<?> routeMatch(Class<? extends Annotation>... annotations) {
        Set<Class<? extends Annotation>> present = new HashSet<>(Arrays.asList(annotations));
        ClassLoader classLoader = InterceptUrlMapRuleHeadRequestTest.class.getClassLoader();
        AnnotationMetadata annotationMetadata = (AnnotationMetadata) Proxy.newProxyInstance(classLoader, new Class<?>[] {AnnotationMetadata.class}, (proxy, method, args) -> {
            if ("hasAnnotation".equals(method.getName()) && args != null && args.length == 1 && args[0] instanceof Class) {
                return present.contains(args[0]);
            }
            throw new UnsupportedOperationException(method.toString());
        });
        return (RouteMatch<?>) Proxy.newProxyInstance(classLoader, new Class<?>[] {RouteMatch.class}, (proxy, method, args) -> {
            if ("getAnnotationMetadata".equals(method.getName())) {
                return annotationMetadata;
            }
            throw new UnsupportedOperationException(method.toString());
        });
    }

    /**
     * A request no route matches.
     */
    private static SecurityRuleResult check(SecurityRule rule, HttpRequest<?> request, @Nullable Authentication authentication) {
        return Mono.from(rule.check(request, null, authentication)).block();
    }

    private static SecurityRuleResult check(SecurityRule rule, RoutedRequest routedRequest, @Nullable Authentication authentication) {
        return Mono.from(rule.check(routedRequest.request, routedRequest.routeMatch, authentication)).block();
    }

    private static SecurityRule rule(InterceptUrlMapPattern... patterns) {
        return new InterceptUrlMapRule(new DefaultRolesFinder(new TokenConfiguration() { })) {
            @Override
            protected List<InterceptUrlMapPattern> getPatternList() {
                return Arrays.asList(patterns);
            }
        };
    }

    private static final class RoutedRequest {
        private final HttpRequest<?> request;
        private final RouteMatch<?> routeMatch;

        private RoutedRequest(HttpRequest<?> request, RouteMatch<?> routeMatch) {
            this.request = request;
            this.routeMatch = routeMatch;
        }
    }
}
