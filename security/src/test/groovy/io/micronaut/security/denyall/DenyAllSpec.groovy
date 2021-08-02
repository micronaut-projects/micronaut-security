package io.micronaut.security.denyall


import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

import javax.annotation.security.DenyAll

class DenyAllSpec extends EmbeddedServerSpecification {

    public static final String controllerPath = '/denyall'

    @Override
    String getSpecName() {
        'DenyAllSpec'
    }

    void "DenyAll collaborators are loaded"() {
        when:
        embeddedServer.applicationContext.getBean(BookController)

        then:
        noExceptionThrown()

        when:
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword)

        then:
        noExceptionThrown()
    }

    def "@DenyAll annotation is equivalent to @Secured('denyAll()')"() {
        when: 'accessing as anonymous an endpoint @Secured("isAnonymous()")'
        client.exchange(HttpRequest.GET("${controllerPath}/index"))

        then:
        noExceptionThrown()

        when: 'accessing as anonymous a @DenyAll endpoint'
        client.exchange(HttpRequest.GET("${controllerPath}/denied"))

        then: '401 is returned'
        def e = thrown(HttpClientResponseException)
        e.response.status == HttpStatus.UNAUTHORIZED

        when: 'when authenticated'
        client.exchange(HttpRequest.GET("${controllerPath}/denied").basicAuth("user", "password"))

        then: 'user is denied with 403'
        e = thrown(HttpClientResponseException)
        e.response.status == HttpStatus.FORBIDDEN
    }

    def "@Secured('denyAll()') endpoints throw 401"() {
        when: 'accessing as anonymous an endpoint @Secured("isAnonymous()")'
        client.exchange(HttpRequest.GET("${controllerPath}/index"))

        then:
        noExceptionThrown()

        when: 'accessing as anonymous a @Secured("denyAll()") endpoint'
        client.exchange(HttpRequest.GET("${controllerPath}/secureddenied"))

        then: '401 is returned'
        def e = thrown(HttpClientResponseException)
        e.response.status == HttpStatus.UNAUTHORIZED
    }

    @Singleton
    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = "DenyAllSpec")
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_USER'])])
        }
    }

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = "DenyAllSpec")
    @Controller(DenyAllSpec.controllerPath)
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class BookController {

        @DenyAll
        @Get("/denied")
        String denied() {
            "You will not see this"
        }

        @Get("/index")
        String index() {
            "You will not see this"
        }

        @Secured(SecurityRule.DENY_ALL)
        @Get("/secureddenied")
        String securedDenyAll() {
            "You will not see this"
        }
    }
}
