package io.micronaut.security.rolesallowed

import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

import javax.annotation.security.RolesAllowed

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

    @Singleton
    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'RolesAllowedSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_USER'])])
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


}
