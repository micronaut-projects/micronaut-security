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
package io.micronaut.security.filters;

import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.inject.ExecutableMethod;
import io.micronaut.management.endpoint.EndpointSensitivityProcessor;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthorizationException;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.rules.SecuredAnnotationRule;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.security.rules.SensitiveEndpointRule;
import io.micronaut.web.router.MethodBasedRouteMatch;
import io.micronaut.web.router.RouteAttributes;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The {@link io.micronaut.web.router.RouteMatch} stored in the request is owned by the request pipeline.
 * Security code must never close it, otherwise the route could execute with released argument binding results.
 */
class SecurityFilterAndRulesRouteMatchNotClosedTest {

    @Test
    void securedAnnotationRuleDoesNotCloseTheRouteMatch() {
        MethodBasedRouteMatch<Object, Object> routeMatch = anonymousRouteMatch();
        HttpRequest<?> request = HttpRequest.GET("/secured");
        RouteAttributes.setRouteMatch(request, routeMatch);

        SecurityRuleResult result = Mono.from(securedAnnotationRule().check(request, null)).block();

        assertEquals(SecurityRuleResult.ALLOWED, result);
        verify(routeMatch, never()).close();
    }

    @Test
    void sensitiveEndpointRuleDoesNotCloseTheRouteMatch() {
        ExecutableMethod<Object, Object> executableMethod = executableMethod();
        MethodBasedRouteMatch<Object, Object> routeMatch = routeMatch();
        when(routeMatch.getExecutableMethod()).thenReturn(executableMethod);
        HttpRequest<?> request = HttpRequest.GET("/endpoint");
        RouteAttributes.setRouteMatch(request, routeMatch);

        SecurityRuleResult result = Mono.from(nonSensitiveEndpointRule(executableMethod).check(request, null)).block();

        assertEquals(SecurityRuleResult.ALLOWED, result);
        verify(routeMatch, never()).close();
    }

    @Test
    void securityFilterDoesNotCloseTheRouteMatchWhenARuleAllowsTheRequest() {
        MethodBasedRouteMatch<Object, Object> routeMatch = anonymousRouteMatch();
        HttpRequest<?> request = HttpRequest.GET("/secured");
        RouteAttributes.setRouteMatch(request, routeMatch);
        ServerFilterChain chain = mock(ServerFilterChain.class);
        when(chain.proceed(request)).thenReturn(Mono.<MutableHttpResponse<?>>just(HttpResponse.ok()));

        MutableHttpResponse<?> response = Flux.from(securityFilter().doFilter(request, chain)).blockFirst();

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.status());
        verify(chain).proceed(request);
        verify(routeMatch, never()).close();
    }

    @Test
    void securityFilterDoesNotCloseTheRouteMatchWhenNoRuleDecides() {
        MethodBasedRouteMatch<Object, Object> routeMatch = routeMatch();
        HttpRequest<?> request = HttpRequest.GET("/unsecured");
        RouteAttributes.setRouteMatch(request, routeMatch);
        ServerFilterChain chain = mock(ServerFilterChain.class);
        Flux<MutableHttpResponse<?>> responses = Flux.from(securityFilter().doFilter(request, chain));

        assertThrows(AuthorizationException.class, responses::blockFirst);

        verify(chain, never()).proceed(any());
        verify(routeMatch, never()).close();
    }

    /**
     * @return A {@link SecurityFilter} with the rules which read the route match, rejecting requests no rule decides.
     */
    private static SecurityFilter securityFilter() {
        SecurityConfiguration securityConfiguration = mock(SecurityConfiguration.class);
        when(securityConfiguration.isRejectNotFound()).thenReturn(true);
        List<SecurityRule<HttpRequest<?>>> rules = List.of(nonSensitiveEndpointRule(executableMethod()), securedAnnotationRule());
        return new SecurityFilter(rules, Collections.emptyList(), securityConfiguration, mock(SecurityFilterConfiguration.class), null);
    }

    private static SecuredAnnotationRule securedAnnotationRule() {
        return new SecuredAnnotationRule(attributes -> Collections.emptyList());
    }

    private static SensitiveEndpointRule nonSensitiveEndpointRule(ExecutableMethod<Object, Object> endpointMethod) {
        EndpointSensitivityProcessor processor = new EndpointSensitivityProcessor(Collections.emptyList(), null, null);
        processor.getEndpointMethods().put(endpointMethod, false);
        return new SensitiveEndpointRule(processor);
    }

    /**
     * @return A route match for a method annotated with {@code @Secured(SecurityRule.IS_ANONYMOUS)}.
     */
    private static MethodBasedRouteMatch<Object, Object> anonymousRouteMatch() {
        MethodBasedRouteMatch<Object, Object> routeMatch = routeMatch();
        when(routeMatch.getAnnotation(Secured.class))
                .thenReturn(AnnotationValue.builder(Secured.class).values(SecurityRule.IS_ANONYMOUS).build());
        when(routeMatch.getValue(Secured.class, String[].class))
                .thenReturn(Optional.of(new String[]{SecurityRule.IS_ANONYMOUS}));
        return routeMatch;
    }

    @SuppressWarnings("unchecked")
    private static MethodBasedRouteMatch<Object, Object> routeMatch() {
        return mock(MethodBasedRouteMatch.class);
    }

    @SuppressWarnings("unchecked")
    private static ExecutableMethod<Object, Object> executableMethod() {
        return mock(ExecutableMethod.class);
    }
}
