package io.micronaut.security.rolesallowed


import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.annotation.security.RolesAllowed
import jakarta.inject.Singleton

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
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', ['ROLE_USER']))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
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
