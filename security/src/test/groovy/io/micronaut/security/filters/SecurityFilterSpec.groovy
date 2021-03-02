package io.micronaut.security.filters

import io.micronaut.core.convert.value.MutableConvertibleValues
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthorizationException
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.rules.ReactiveSecurityRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.web.router.RouteMatch
import io.reactivex.Flowable
import io.reactivex.schedulers.Schedulers
import io.reactivex.subscribers.TestSubscriber
import spock.lang.Unroll

import java.util.concurrent.TimeUnit

import static io.micronaut.security.rules.SecurityRuleResult.ALLOWED
import static io.micronaut.security.rules.SecurityRuleResult.REJECTED
import static io.micronaut.security.rules.SecurityRuleResult.UNKNOWN

class SecurityFilterSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecurityFilterSpec'
    }

    @Unroll('#description')
    def "Filter order is correct"() {
        given:
        SecurityFilter filter = new SecurityFilter(rules, reactiveRules, List.of(), Stub(SecurityConfiguration.class))

        HttpRequest request = Stub(HttpRequest.class) {
            getPath() >> new URI('/')
            getMethod() >> HttpMethod.GET
            getAttributes() >> Stub(MutableConvertibleValues.class)
        }

        ServerFilterChain chain = Stub(ServerFilterChain.class) {
            proceed(request) >> {allowed != null ? Flowable.just(HttpResponse.ok()) : Flowable.empty()}
        }

        RouteMatch<?> routeMatch = Stub(RouteMatch.class)
        Authentication authentication = Stub(Authentication.class)

        TestSubscriber<HttpResponse<?>> testSubscriber = new TestSubscriber<>()

        expect:
        filter.checkRules(request, chain, routeMatch, authentication).subscribe(testSubscriber)
        testSubscriber.await()

        if (allowed) {
            testSubscriber.completions() == 1
            !testSubscriber.timeout
            testSubscriber.errorCount() == 0
            testSubscriber.valueCount() == 1
            testSubscriber.values() == [HttpResponse.ok()]
        } else {
            testSubscriber.completions() == 0
            !testSubscriber.timeout
            testSubscriber.errorCount() == 1
            testSubscriber.errors().get(0).class == AuthorizationException.class
            testSubscriber.valueCount() == 0
        }

        where:
        rules                       | reactiveRules                           | allowed | description
        []                          | []                                      | false   | 'No rules'
        [securityRule(0, ALLOWED)]  | []                                      | true    | 'One SecurityRule - allowed'
        [securityRule(0, REJECTED)] | []                                      | false   | 'One SecurityRule - rejected'
        [securityRule(0, UNKNOWN)]  | []                                      | false   | 'One SecurityRule - unknown'
        []                          | [reactiveSecurityRule(0, ALLOWED, 0)]   | true    | 'One ReactiveSecurityRule - allowed'
        []                          | [reactiveSecurityRule(0, REJECTED, 0)]  | false   | 'One ReactiveSecurityRule - rejected'
        []                          | [reactiveSecurityRule(0, UNKNOWN, 0)]   | false   | 'One ReactiveSecurityRule - unknown'

        // Non-reactive first
        [securityRule(0, UNKNOWN)]  | [reactiveSecurityRule(1, ALLOWED, 0)]   | true    | 'Mixed - rule unknown => reactive allowed, no delay'
        [securityRule(0, ALLOWED)]  | [reactiveSecurityRule(1, REJECTED, 0)]  | true    | 'Mixed - rule allowed => reactive rejected, no delay'
        [securityRule(0, UNKNOWN)]  | [reactiveSecurityRule(1, REJECTED, 0)]  | false   | 'Mixed - rule unknown => reactive rejected, no delay'
        [securityRule(0, REJECTED)] | [reactiveSecurityRule(1, ALLOWED, 0)]   | false   | 'Mixed - rule rejected => reactive allowed, no delay'
        [securityRule(0, UNKNOWN)]  | [reactiveSecurityRule(1, UNKNOWN, 0)]   | false   | 'Mixed - rule unknown => reactive unknown, no delay'

        // Reactive first
        [securityRule(1, ALLOWED)]  | [reactiveSecurityRule(0, UNKNOWN, 0)]   | true    | 'Mixed - reactive unknown => rule allowed, no delay'
        [securityRule(1, REJECTED)] | [reactiveSecurityRule(0, ALLOWED, 0)]   | true    | 'Mixed - reactive allowed => rule rejected, no delay'
        [securityRule(1, REJECTED)] | [reactiveSecurityRule(0, UNKNOWN, 0)]   | false   | 'Mixed - reactive unknown => rule rejected, no delay'
        [securityRule(1, ALLOWED)]  | [reactiveSecurityRule(0, REJECTED, 0)]  | false   | 'Mixed - reactive rejected => rule allowed, no delay'
        [securityRule(1, UNKNOWN)]  | [reactiveSecurityRule(0, UNKNOWN, 0)]   | false   | 'Mixed - reactive unknown => rule unknown, no delay'

        // With delays (cause the reactive to evaluate async and slowly, ensure still correct response)
        [securityRule(1, REJECTED)] | [reactiveSecurityRule(0, ALLOWED, 100)]  | true   | 'Mixed - reactive allowed => rule rejected, 100ms delay'
        [securityRule(1, ALLOWED)]  | [reactiveSecurityRule(0, REJECTED, 100)] | false  | 'Mixed - reactive rejected => rule allowed, 100ms delay'

        // Multiple of same type, injection sort order incorrect
        [securityRule(1, REJECTED), securityRule(0, ALLOWED)]  | [] | true  | 'Multiple - rule 0 rejected => rule 1 allowed, no delay'
        [] | [reactiveSecurityRule(1, REJECTED, 0), reactiveSecurityRule(0, ALLOWED, 0)] | true  | 'Multiple - reactive 0 rejected => reactive 1 allowed, no delay'
    }

    SecurityRule securityRule(int order, SecurityRuleResult result) {
        Stub(SecurityRule.class) {
            check(_ as HttpRequest, _ as RouteMatch, _ as Map) >> result
            getOrder() >> order
        }
    }

    ReactiveSecurityRule reactiveSecurityRule(int order, SecurityRuleResult result, long delayMs) {
        Stub(ReactiveSecurityRule.class) {
            check(_ as HttpRequest, _ as RouteMatch, _ as Map) >>
                    Flowable.timer(delayMs, TimeUnit.MILLISECONDS)
                            .subscribeOn(Schedulers.io())
                            .flatMap((l) -> Flowable.just(result))
            getOrder() >> order
        }
    }
}
