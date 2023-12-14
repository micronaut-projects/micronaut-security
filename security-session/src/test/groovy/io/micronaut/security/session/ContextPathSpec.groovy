package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono

class ContextPathSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'ContextPathSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.authentication': 'session'
        ]
    }

    void "redirect configuration uses server-context-path"() {
        when:
        String response = client.retrieve('/foo')

        then:
        noExceptionThrown()
        'Home' == response

        when:
        client.retrieve('/')

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.NOT_FOUND == e.status

        when:
        HttpRequest<?> request = HttpRequest.POST("/foo/login", [username: 'user', password: 'password'])
        client.exchange(request)

        then:
        noExceptionThrown()

        when:
        request = HttpRequest.POST("/foo/logout", [:])
        client.exchange(request)

        then:
        noExceptionThrown()

        when:
        request = HttpRequest.POST("/foo/login", [username: 'user', password: 'bogus'])
        client.exchange(request)

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'ContextPathSpec')
    @Singleton
    static class MockAuthenticationProvider<T, I, S> implements ReactiveAuthenticationProvider<T, I, S> {

        @Override
        Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
            return Mono.<AuthenticationResponse>create(emitter -> {
                if (authenticationRequest.identity =="user" && authenticationRequest.secret == "password") {
                    emitter.success(AuthenticationResponse.success("user"))
                } else {
                    emitter.error(AuthenticationResponse.exception());
                }
            })
        }
    }

    @Requires(property = 'spec.name', value = 'ContextPathSpec')
    @Controller
    static class HomeController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            "Home"
        }
    }
}
