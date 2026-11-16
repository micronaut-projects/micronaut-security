package io.micronaut.security.token

import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.authentication.AuthenticationMode
import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification
import spock.lang.Unroll

class DefaultRolesFinderSpec extends Specification {

    TokenConfiguration tokenConfiguration = new TokenConfiguration() {}

    void "default constructor keeps role comparison case sensitive"() {
        given:
        DefaultRolesFinder rolesFinder = new DefaultRolesFinder(tokenConfiguration)

        expect:
        rolesFinder.hasAnyRequiredRoles(['ROLE_ADMIN'], ['ROLE_ADMIN'])
        !rolesFinder.hasAnyRequiredRoles(['role_admin'], ['ROLE_ADMIN'])
    }

    @Unroll
    void "configured case insensitive role comparison for #requiredRoles and #grantedRoles is #expected"() {
        given:
        SecurityConfiguration securityConfiguration = Stub(SecurityConfiguration) {
            isRolesCaseSensitive() >> false
        }
        DefaultRolesFinder rolesFinder = new DefaultRolesFinder(tokenConfiguration, securityConfiguration)

        expect:
        rolesFinder.hasAnyRequiredRoles(requiredRoles, grantedRoles) == expected

        where:
        requiredRoles        | grantedRoles   || expected
        ['role_admin']       | ['ROLE_ADMIN'] || true
        ['role_admin']       | ['ROLE_USER']  || false
        []                   | ['ROLE_ADMIN'] || false
        ['role_admin']       | []             || false
        [null]               | [null]         || true
        [null, 'role_admin'] | ['ROLE_ADMIN'] || true
    }

    void "security configuration roles case-sensitive default is true"() {
        given:
        SecurityConfiguration securityConfiguration = new SecurityConfiguration() {
            @Override
            List<String> getIpPatterns() {
                []
            }

            @Override
            List getInterceptUrlMap() {
                []
            }

            @Override
            boolean isInterceptUrlMapPrependPatternWithContextPath() {
                true
            }

            @Override
            AuthenticationMode getAuthentication() {
                null
            }
        }

        expect:
        securityConfiguration.rolesCaseSensitive
    }
}
