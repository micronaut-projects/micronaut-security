package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

class SecuredRolesCaseSensitiveSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecuredRolesCaseSensitiveSpec'
    }

    void "@Secured annotation value is case sensitive"() {
        when:
        client.exchange(HttpRequest.GET("/uppercase").basicAuth('user', 'password'), String)

        then:
        noExceptionThrown()

        when:
        client.exchange(HttpRequest.GET("/lowercase").basicAuth('user', 'password'), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN
    }

    @Requires(property = 'spec.name', value = 'SecuredRolesCaseSensitiveSpec')
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
    @Requires(property = 'spec.name', value = 'SecuredRolesCaseSensitiveSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', ['ROLE_USER']))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }
}
