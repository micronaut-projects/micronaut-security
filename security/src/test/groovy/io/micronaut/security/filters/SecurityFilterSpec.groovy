package io.micronaut.security.filters

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.ReactiveSecurityRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import io.micronaut.web.router.RouteMatch
import io.reactivex.Flowable
import io.reactivex.schedulers.Schedulers
import org.jetbrains.annotations.Nullable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.util.concurrent.TimeUnit

import static io.micronaut.security.rules.SecurityRuleResult.ALLOWED
import static io.micronaut.security.rules.SecurityRuleResult.REJECTED
import static io.micronaut.security.rules.SecurityRuleResult.UNKNOWN

@MicronautTest(rebuildContext = true)
class SecurityFilterSpec extends EmbeddedServerSpecification {

    static final String magicString = 'Hello world'

    @Override
    String getSpecName() {
        'SecurityFilterSpec'
    }

    @Property(name = "disable.all.rules", value = StringUtils.TRUE)
    def 'No rules'() {
        given:
        HttpRequest request = HttpRequest.GET('/securityFilter')

        when:
        client.exchange(request, String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Property(name = "disable.all.rules", value = StringUtils.FALSE)
    def 'With rules - authorized'() {
        given:
        HttpRequest request = HttpRequest.GET('/securityFilter')

        when:
        Rule1.result = ruleValues[0]
        Rule2.result = ruleValues[1]
        Rule3.result = ruleValues[2]

        Rule1.delayMs = delayValue

        HttpResponse<String> response = client.exchange(request, String)

        then:
        response != null
        response.getStatus() == HttpStatus.OK
        response.body() != null
        response.body() == magicString

        where:
        ruleValues                    | delayValue | description
        [ALLOWED, REJECTED, REJECTED] | 0          | 'first rule - allowed'
        [UNKNOWN, ALLOWED, REJECTED]  | 0          | 'second rule - allowed'
        [UNKNOWN, UNKNOWN, ALLOWED]   | 0          | 'third rule - allowed'

        // With delays (cause the reactive to evaluate async and slowly, ensure still correct response)
        [ALLOWED, REJECTED, REJECTED] | 100        | 'first allowed after 100ms delay'

    }

    @Property(name = "disable.all.rules", value = StringUtils.FALSE)
    def 'With rules - unauthorized'() {
        given:
        HttpRequest request = HttpRequest.GET('/securityFilter')

        when:
        Rule1.result = ruleValues[0]
        Rule2.result = ruleValues[1]
        Rule3.result = ruleValues[2]

        Rule1.delayMs = delayValue

        client.exchange(request, String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED

        where:
        ruleValues                            | delayValue | description
        [UNKNOWN, UNKNOWN, UNKNOWN]  | 0      | 'all unknown'
        [REJECTED, ALLOWED, UNKNOWN] | 0      | 'first rule - rejected'
        [UNKNOWN, REJECTED, ALLOWED] | 0      | 'second rule - rejected'
        [UNKNOWN, UNKNOWN, REJECTED] | 0      | 'third rule - rejected'

        // With delays (cause the reactive to evaluate async and slowly, ensure still correct response)
        [REJECTED, ALLOWED, ALLOWED] | 100    | 'first rejected after 100ms delay'
    }

    @Singleton
    @Requires(property = "spec.name", value = 'SecurityFilterSpec')
    @Requires(property = "disable.all.rules", notEquals = StringUtils.TRUE)
    static class Rule1 implements ReactiveSecurityRule {
        static SecurityRuleResult result = UNKNOWN
        static int delayMs = 0

        @Override
        Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
            return Flowable.timer(delayMs, TimeUnit.MILLISECONDS)
                    .subscribeOn(Schedulers.io())
                    .flatMap((l) -> Flowable.just(result))
        }

        @Override
        int getOrder() {
            return HIGHEST_PRECEDENCE
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = 'SecurityFilterSpec')
    @Requires(property = "disable.all.rules", notEquals = StringUtils.TRUE)
    static class Rule2 implements SecurityRule {
        static SecurityRuleResult result = UNKNOWN

        @Override
        SecurityRuleResult check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
            return result
        }

        @Override
        int getOrder() {
            return HIGHEST_PRECEDENCE + 1
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = 'SecurityFilterSpec')
    @Requires(property = "disable.all.rules", notEquals = StringUtils.TRUE)
    static class Rule3 implements ReactiveSecurityRule {
        static SecurityRuleResult result = UNKNOWN

        @Override
        Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims) {
            return Flowable.just(result)
        }

        @Override
        int getOrder() {
            return HIGHEST_PRECEDENCE + 2
        }
    }

    @Requires(property = "spec.name", value = 'SecurityFilterSpec')
    @Controller('/securityFilter')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class TestController {
        @Get
        String get() {
            return magicString
        }
    }
}
