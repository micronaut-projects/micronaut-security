package io.micronaut.security.rolesallowed

import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

import jakarta.annotation.security.RolesAllowed

class RolesAllowedSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'RolesAllowedSpec'
    }

    public static final String controllerPath = '/rolesallowed'

    void "PermitAllSpec collaborators are loaded"() {
        when:
        applicationContext.getBean(BookController)

        then:
        noExceptionThrown()

        when:
        applicationContext.getBean(AuthenticationProviderUserPassword)

        then:
        noExceptionThrown()
    }

    def "@RolesAllowed(['ROLE_ADMIN', 'ROLE_USER']) annotation is equivalent to @Secured(['ROLE_ADMIN', 'ROLE_USER'])"() {
        when:
        client.exchange(HttpRequest.GET("${controllerPath}/books").basicAuth("user", "password"))

        then:
        noExceptionThrown()
    }

    def "methods in a controller inherit @RolesAllowed at class level"() {
        when:
        client.exchange(HttpRequest.GET("${controllerPath}/classlevel").basicAuth("user", "password"))

        then:
        noExceptionThrown()
    }

    def "@RolesAllowed(['ROLE_ADMIN', 'ROLE_MANAGER']) annotation is equivalent to @Secured(['ROLE_ADMIN', 'ROLE_MANAGER']), if user has only ROLE_USER access is forbidden "() {
        when:
        client.exchange(HttpRequest.GET("${controllerPath}/forbidenbooks").basicAuth("user", "password"))

        then:
        def e = thrown(HttpClientResponseException)

        e.response.status() == HttpStatus.FORBIDDEN
    }

    def "Both @Secured and @RolesAllowed should not be used in the same method"() {
        when:
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/both/securedfirstrolesallowedsecond").basicAuth("sherlock", "password"))

        then:
        noExceptionThrown()
        HttpStatus.ACCEPTED == response.status()

        when: // @Secured is used not @RolesAllowed
        response = client.exchange(HttpRequest.GET("/both/securedfirstrolesallowedsecond").basicAuth("user", "password"))

        then:
        noExceptionThrown()

        HttpStatus.ACCEPTED == response.status()

        when:
        response = client.exchange(HttpRequest.GET("/both/rolesallowedfirstsecuredsecond").basicAuth("sherlock", "password"))

        then:
        noExceptionThrown()
        HttpStatus.ACCEPTED == response.status()

        when: // @RolesAllowed is used not @Secured
        response = client.exchange(HttpRequest.GET("/both/rolesallowedfirstsecuredsecond").basicAuth("user", "password"))

        then:
        HttpClientResponseException ex = thrown()
        HttpStatus.FORBIDDEN == ex.status
    }

    @Singleton
    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'RolesAllowedSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_USER']), new SuccessAuthenticationScenario('sherlock', ['ROLE_DETECTIVE'])])
        }
    }

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'RolesAllowedSpec')
    @RolesAllowed(['ROLE_USER'])
    @Controller(RolesAllowedSpec.controllerPath)
    static class BookController {

        @RolesAllowed(['ROLE_USER', 'ROLE_ADMIN'])
        @Get("/books")
        Map<String, Object> list() {
            [books: ['Building Microservice', 'Release it']]
        }

        @Get("/classlevel")
        Map<String, Object> classlevel() {
            [books: ['Building Microservice', 'Release it']]
        }

        @RolesAllowed(['ROLE_ADMIN', 'ROLE_MANAGER'])
        @Get("/forbidenbooks")
        Map<String, Object> forbiddenList() {
            [books: ['Building Microservice', 'Release it']]
        }
    }


    @Controller("/both")
    static class SecuredAndRolesAllowed {
        @Status(HttpStatus.ACCEPTED)
        @Get("/securedfirstrolesallowedsecond")
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @RolesAllowed("ROLE_DETECTIVE")
        void securedfirstrolesallowedsecond() {
        }

        @Status(HttpStatus.ACCEPTED)
        @Get("/rolesallowedfirstsecuredsecond")
        @RolesAllowed("ROLE_DETECTIVE")
        @Secured(SecurityRule.IS_AUTHENTICATED)
        void rolesallowedfirstsecuredsecond() {
        }
    }
}
