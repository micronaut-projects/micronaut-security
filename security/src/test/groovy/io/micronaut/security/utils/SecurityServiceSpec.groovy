package io.micronaut.security.utils

import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

class SecurityServiceSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecurityServiceSpec'
    }
    void "SecurityServiceSpec collaborators are loaded"() {
        when:
        applicationContext.getBean(SecurityServiceController)

        then:
        noExceptionThrown()

        when:
        applicationContext.getBean(AuthenticationProviderUserPassword)

        then:
        noExceptionThrown()
    }

    void "verify SecurityService.isAuthenticated()"() {
        when:
        Boolean authenticated = client.retrieve(HttpRequest.GET("/securityutils/authenticated")
                .accept(MediaType.TEXT_PLAIN)
                .basicAuth("user", "password"), Boolean)

        then:
        authenticated

        when:
        authenticated = client.retrieve(HttpRequest.GET("/securityutils/authenticated").accept(MediaType.TEXT_PLAIN), Boolean)

        then:
        !authenticated
    }

    void "verify SecurityService.isCurrentUserInRole()"() {
        when:
        HttpRequest request = HttpRequest.GET("/securityutils/roles?role=ROLE_USER").accept(MediaType.TEXT_PLAIN)
                .basicAuth("user", "password")
        Boolean hasRole = client.retrieve(request, Boolean)

        then:
        hasRole

        when:
        request = HttpRequest.GET("/securityutils/roles?role=ROLE_ADMIN").accept(MediaType.TEXT_PLAIN)
                .basicAuth("user", "password")
        hasRole = client.retrieve(request, Boolean)

        then:
        !hasRole

        when:
        request = HttpRequest.GET("/securityutils/roles?role=ROLE_USER").accept(MediaType.TEXT_PLAIN)
        hasRole = client.retrieve(request, Boolean)

        then:
        !hasRole
    }

    void "verify SecurityService.currentUserLogin()"() {
        when:
        String username = client.retrieve(HttpRequest.GET("/securityutils/currentuser")
                .accept(MediaType.TEXT_PLAIN)
                .basicAuth("user", "password"), String)

        then:
        username == "user"

        when:
        username = client.retrieve(HttpRequest.GET("/securityutils/currentuser").accept(MediaType.TEXT_PLAIN), String)

        then:
        username == "Anonymous"
    }

    @Singleton
    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'SecurityServiceSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_USER'])])
        }
    }

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'SecurityServiceSpec')
    @Controller('/securityutils')
    static class SecurityServiceController {

        private final SecurityService securityService

        SecurityServiceController(SecurityService securityService) {
            this.securityService = securityService
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("isAnonymous()")
        @Get("/authenticated")
        boolean authenticated() {
            securityService.isAuthenticated()
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("isAnonymous()")
        @Get("/currentuser")
        String currentuser() {
            Optional<String> str = securityService.username()
            str.map { m -> m}.orElse("Anonymous")
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("isAnonymous()")
        @Get("/roles{?role}")
        Boolean roles(@Nullable String role) {
            securityService.hasRole(role)
        }
    }
}
