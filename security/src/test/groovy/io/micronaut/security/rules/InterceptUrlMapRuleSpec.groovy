
package io.micronaut.security.rules

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.security.config.InterceptUrlMapPattern
import io.micronaut.security.token.DefaultRolesFinder
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Issue
import spock.lang.Specification
import spock.lang.Unroll

class InterceptUrlMapRuleSpec extends Specification {

    @Unroll
    void "test query arguments are ignored by matching logic"() {

        given: 'a token configuration'
        TokenConfiguration configuration = Mock()

        and: 'the expected mock behaviour'
        (0..1) * configuration.isEnabled() >> true
        (0..1) * configuration.rolesName >> "roles"
        0 * _

        and:
        SecurityRule rule = new InterceptUrlMapRule(configuration) {
            @Override
            protected List<InterceptUrlMapPattern> getPatternList() {
                [new InterceptUrlMapPattern("/foo", ["ROLE_ADMIN"], HttpMethod.GET)]
            }
        }

        expect:
        rule.check(HttpRequest.GET(uri), null, [roles: ["ROLE_ADMIN"]]) == expectedResult

        where:
        uri             || expectedResult
        '/foo'          || SecurityRuleResult.ALLOWED
        '/foo?bar=true' || SecurityRuleResult.ALLOWED
        '/foo/bar'      || SecurityRuleResult.UNKNOWN
    }

    @Issue("https://github.com/micronaut-projects/micronaut-core/issues/1511")
    @Unroll
    void "An http #method request to '#uri' should result in the security result #expectedResult"() {

        given: 'a token configuration'
        TokenConfiguration configuration = Mock()

        and: 'the expected mock behaviour'
        (0..1) * configuration.isEnabled() >> true
        (0..1) * configuration.rolesName >> "roles"
        0 * _

        and: ''
        SecurityRule rule = new InterceptUrlMapRule(new DefaultRolesFinder(configuration)) {
            @Override
            protected List<InterceptUrlMapPattern> getPatternList() {
                [
                        new InterceptUrlMapPattern("/v1/sessions/**", ["isAuthenticated()"], null),
                        new InterceptUrlMapPattern("/v1/sessions/**", ["isAnonymous()"], HttpMethod.OPTIONS)
                ]
            }
        }

        expect:
        rule.check(request, null, null) == expectedResult

        where:
        request                                       || expectedResult
        HttpRequest.OPTIONS('/v1/sessions/123')       || SecurityRuleResult.ALLOWED
        HttpRequest.OPTIONS('/v1/sessions/')          || SecurityRuleResult.ALLOWED
        HttpRequest.GET('/v1/sessions/123')           || SecurityRuleResult.REJECTED
        HttpRequest.GET('/v1/sessions/')              || SecurityRuleResult.REJECTED
        HttpRequest.POST('/v1/sessions/123', 'body')  || SecurityRuleResult.REJECTED
        HttpRequest.POST('/v1/sessions/', 'body')     || SecurityRuleResult.REJECTED
        HttpRequest.PUT('/v1/sessions/123', 'body')   || SecurityRuleResult.REJECTED
        HttpRequest.PUT('/v1/sessions/', 'body')      || SecurityRuleResult.REJECTED
        HttpRequest.DELETE('/v1/sessions/123')        || SecurityRuleResult.REJECTED
        HttpRequest.DELETE('/v1/sessions/')           || SecurityRuleResult.REJECTED
        HttpRequest.HEAD('/v1/sessions/123')          || SecurityRuleResult.REJECTED
        HttpRequest.HEAD('/v1/sessions/')             || SecurityRuleResult.REJECTED
        HttpRequest.PATCH('/v1/sessions/123', 'body') || SecurityRuleResult.REJECTED
        HttpRequest.PATCH('/v1/sessions/', 'body')    || SecurityRuleResult.REJECTED

        method = request.method
        uri = request.uri
    }
}
