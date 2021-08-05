package io.micronaut.security.rules

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.security.config.InterceptUrlMapPattern
import io.micronaut.security.config.SecurityConfigurationProperties
import io.micronaut.security.token.DefaultRolesFinder
import io.micronaut.security.token.RolesFinder
import io.micronaut.security.token.config.TokenConfiguration
import reactor.core.publisher.Mono
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class ConfigurationInterceptUrlMapRuleSpec extends Specification {

    @Shared
    TokenConfiguration tokenConfiguration = new TokenConfiguration() {
        @Override
        String getRolesName() {
            'roles'
        }

        @Override
        String getNameKey() {
            'username'
        }
    }
    @Shared
    RolesFinder rolesFinder = new DefaultRolesFinder(tokenConfiguration)

    @Unroll('#description')
    def "verify behaviour different intercept url map configurations"(SecurityRuleResult securityRuleResult, List<InterceptUrlMapPattern> interceptUrlMap, String description) {
        given:
        def securityConfiguration = Stub(SecurityConfigurationProperties) {
            getInterceptUrlMap() >> interceptUrlMap
        }
        def request = Stub(HttpRequest) {
            getUri() >> new URI('/books')
            getMethod() >> HttpMethod.GET
        }
        ConfigurationInterceptUrlMapRule provider = new ConfigurationInterceptUrlMapRule(rolesFinder, securityConfiguration)

        expect:
        Mono.from(provider.check(request, null, null)).block() == securityRuleResult

        where:
        securityRuleResult          | interceptUrlMap                                                                               | description
        SecurityRuleResult.ALLOWED  | [new InterceptUrlMapPattern('/books',[SecurityRule.IS_ANONYMOUS], HttpMethod.GET)]     | 'if interceptUrlMap defines anonymous and GET method, result is ALLOWED'
        SecurityRuleResult.ALLOWED  | [new InterceptUrlMapPattern('/books',[SecurityRule.IS_ANONYMOUS], null)]    | 'if interceptUrlMap defines anonymous and no HTTP method, result is ALLOWED'
        SecurityRuleResult.REJECTED | [new InterceptUrlMapPattern('/books',['ROLE_ADMIN'], HttpMethod.GET)]                  | 'if interceptUrlMap defines a neccessary role and GET method, result is REJECTED'
    }

    @Unroll("comparing required: #requiredRoles and granted should return #description")
    def 'verify compare role behaviour'(List<String> requiredRoles, List<String> grantedRoles, SecurityRuleResult expected, String description) {
        given:
        ConfigurationInterceptUrlMapRule provider = new ConfigurationInterceptUrlMapRule(rolesFinder, Mock(SecurityConfigurationProperties))

        expect:
        expected == Mono.from(provider.compareRoles(requiredRoles, grantedRoles)).block()

        where:
        requiredRoles                | grantedRoles                                     | expected
        ['ROLE_ADMIN', 'ROLE_USER']  | ['ROLE_ADMIN', 'ROLE_USER']                      | SecurityRuleResult.ALLOWED
        ['isAuthenticated()']        | ['ROLE_ADMIN', 'ROLE_USER', 'isAuthenticated()'] | SecurityRuleResult.ALLOWED
        ['ROLE_ADMIN', 'ROLE_USER']  | ['ROLE_USER']                                    | SecurityRuleResult.ALLOWED
        ['ROLE_ADMIN']               | ['ROLE_USER']                                    | SecurityRuleResult.REJECTED
        ['isAnonymous()']            | [SecurityRule.IS_ANONYMOUS]                      | SecurityRuleResult.ALLOWED
        ['isAuthenticated()']        | [SecurityRule.IS_AUTHENTICATED]                  | SecurityRuleResult.ALLOWED
        description = expected == SecurityRuleResult.ALLOWED ? 'Allowed' : 'Rejected'
    }
}
