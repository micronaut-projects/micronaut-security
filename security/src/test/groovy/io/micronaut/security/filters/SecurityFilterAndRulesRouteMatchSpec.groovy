package io.micronaut.security.filters

import io.micronaut.core.annotation.AnnotationValue
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthorizationException
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.rules.SecuredAnnotationRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.token.RolesFinder
import io.micronaut.web.router.MethodBasedRouteMatch
import io.micronaut.web.router.RouteAttributes
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import spock.lang.Specification

/**
 * The {@link io.micronaut.web.router.RouteMatch} stored in the request is owned by the request pipeline.
 * Security code must never close it, otherwise the route could execute with released argument binding results.
 */
class SecurityFilterAndRulesRouteMatchSpec extends Specification {

    void "SecuredAnnotationRule does not close the request route match"() {
        given:
        MethodBasedRouteMatch routeMatch = Mock()
        HttpRequest<?> request = HttpRequest.GET('/secured')
        RouteAttributes.setRouteMatch(request, routeMatch)
        SecuredAnnotationRule rule = new SecuredAnnotationRule(new NoRolesFinder())

        when:
        SecurityRuleResult result = Mono.from(rule.check(request, null)).block()

        then:
        result == SecurityRuleResult.ALLOWED
        _ * routeMatch.getAnnotation(Secured) >> AnnotationValue.builder(Secured).values(SecurityRule.IS_ANONYMOUS).build()
        _ * routeMatch.getValue(Secured, String[]) >> Optional.of([SecurityRule.IS_ANONYMOUS] as String[])
        0 * routeMatch.close()
    }

    void "SensitiveEndpointRule does not close the request route match"() {
        given:
        ExecutableMethod executableMethod = Stub()
        MethodBasedRouteMatch routeMatch = Mock()
        HttpRequest<?> request = HttpRequest.GET('/endpoint')
        RouteAttributes.setRouteMatch(request, routeMatch)
        SensitiveEndpointRule rule = new SensitiveEndpointRule(sensitivityProcessor(executableMethod, false))

        when:
        SecurityRuleResult result = Mono.from(rule.check(request, null)).block()

        then:
        result == SecurityRuleResult.ALLOWED
        _ * routeMatch.getExecutableMethod() >> executableMethod
        0 * routeMatch.close()
    }

    void "SecurityFilter and rules do not close the request route match when a rule allows the request"() {
        given:
        MethodBasedRouteMatch routeMatch = Mock()
        HttpRequest<?> request = HttpRequest.GET('/secured')
        RouteAttributes.setRouteMatch(request, routeMatch)
        ServerFilterChain chain = Mock()
        SecurityFilter filter = securityFilter([
                new SensitiveEndpointRule(sensitivityProcessor(Stub(ExecutableMethod), false)),
                new SecuredAnnotationRule(new NoRolesFinder())
        ], true)

        when:
        MutableHttpResponse<?> response = Flux.from(filter.doFilter(request, chain)).blockFirst()

        then:
        response.status().code == 200
        _ * routeMatch.getAnnotation(Secured) >> AnnotationValue.builder(Secured).values(SecurityRule.IS_ANONYMOUS).build()
        _ * routeMatch.getValue(Secured, String[]) >> Optional.of([SecurityRule.IS_ANONYMOUS] as String[])
        1 * chain.proceed(request) >> Mono.just(HttpResponse.ok())
        0 * routeMatch.close()
    }

    void "SecurityFilter does not close the request route match when no rule authorizes or rejects the request"() {
        given:
        MethodBasedRouteMatch routeMatch = Mock()
        HttpRequest<?> request = HttpRequest.GET('/unsecured')
        RouteAttributes.setRouteMatch(request, routeMatch)
        ServerFilterChain chain = Mock()
        SecurityFilter filter = securityFilter([
                new SensitiveEndpointRule(sensitivityProcessor(Stub(ExecutableMethod), false)),
                new SecuredAnnotationRule(new NoRolesFinder())
        ], true)

        when:
        Flux.from(filter.doFilter(request, chain)).blockFirst()

        then:
        thrown(AuthorizationException)
        0 * chain.proceed(_)
        0 * routeMatch.close()
    }

    private static EndpointSensitivityProcessor sensitivityProcessor(ExecutableMethod method, boolean sensitive) {
        EndpointSensitivityProcessor processor = new EndpointSensitivityProcessor([], null, null)
        processor.endpointMethods.put(method, sensitive)
        processor
    }

    private SecurityFilter securityFilter(List<SecurityRule<HttpRequest<?>>> rules, boolean rejectNotFound) {
        SecurityConfiguration securityConfiguration = Stub() {
            isRejectNotFound() >> rejectNotFound
        }
        new SecurityFilter(rules, [], securityConfiguration, Stub(SecurityFilterConfiguration), null)
    }

    private static class NoRolesFinder implements RolesFinder {
        @Override
        List<String> resolveRoles(Map<String, Object> attributes) {
            []
        }
    }
}
