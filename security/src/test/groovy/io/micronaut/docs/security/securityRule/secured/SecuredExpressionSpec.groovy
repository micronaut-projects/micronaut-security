package io.micronaut.docs.security.securityRule.secured

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class SecuredExpressionSpec extends Specification {
    @Shared
    Map<String, Object> config = [
            'spec.name': 'SecuredExpressionSpec',
            'micronaut.http.client.read-timeout': '3600s'
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

    void "verify you can access an endpoint annotated with @Secured() expression with an authenticated user"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated").basicAuth("sherlock", "password"))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated").basicAuth("moriarty", "password"))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/expression").basicAuth("sherlock", "password"))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/expression").basicAuth("moriarty", "password"))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN

        when:
        client.toBlocking().exchange(HttpRequest.GET("/authenticated/expression").basicAuth("watson", "password"))

        then:
        e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Requires(property = "spec.name", value = "SecuredExpressionSpec")
    @Controller("/authenticated")
    static class SecuredExpressionController {

        @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/expression")
        String authenticationExpressionFromContext(Authentication authentication) {
            return authentication.getName() + " is authenticated"
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get()
        String authenticated(Authentication authentication) {
            return authentication.getName() + " is authenticated"
        }
    }


    @Singleton
    @Requires(property = 'spec.name', value = 'SecuredExpressionSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock', ['ROLE_ADMIN'], [email: 'sherlock@micronaut.example']),
                   new SuccessAuthenticationScenario('moriarty', ['ROLE_ADMIN'], [email: 'moriarty@micronaut.example'])])
        }
    }
}

