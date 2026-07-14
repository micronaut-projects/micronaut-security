package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.token.RolesFinder
import io.micronaut.security.utils.DefaultSecurityService
import io.micronaut.security.utils.SecurityService
import jakarta.inject.Singleton

import java.security.Principal

class SecuredRolesCaseInsensitiveConfigurationSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecuredRolesCaseInsensitiveConfigurationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.roles-case-sensitive': false]
    }

    void "@Secured annotation value can be case insensitive"() {
        when:
        client.exchange(HttpRequest.GET("/uppercase").basicAuth('user', 'password'), String)

        then:
        noExceptionThrown()

        when:
        client.exchange(HttpRequest.GET("/lowercase").basicAuth('user', 'password'), String)

        then:
        noExceptionThrown()
    }

    void "SecurityService::hasRole can be case insensitive"() {
        when:
        Authentication authentication = Authentication.build("sherlock", ["ROLE_DETECTIVE"])
        SecurityService securityService = new CustomSecurityService(applicationContext.getBean(RolesFinder), authentication)

        then:
        securityService.hasRole('ROLE_DETECTIVE')

        and:
        securityService.hasRole('role_detective')
    }

    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveConfigurationSpec')
    @Controller
    static class RolesCaseInsensitiveController {

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(["role_user"])
        @Get("/lowercase")
        String lowercase(Principal principal) {
            principal.name
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(["ROLE_USER"])
        @Get("/uppercase")
        String uppercase(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveConfigurationSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_USER'])])
        }
    }

    @Requires(property = 'spec.name', value = 'SecuredRolesCaseInsensitiveConfigurationSpec')
    static class CustomSecurityService extends DefaultSecurityService {

        Authentication authentication

        CustomSecurityService(RolesFinder rolesFinder, Authentication authentication) {
            super(rolesFinder)
            this.authentication = authentication
        }

        @Override
        Optional<Authentication> getAuthentication() {
            Optional.of(authentication)
        }
    }
}
