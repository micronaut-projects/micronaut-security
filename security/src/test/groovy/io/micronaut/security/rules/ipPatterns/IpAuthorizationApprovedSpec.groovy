package io.micronaut.security.rules.ipPatterns

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
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.rules.SecurityRule
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import jakarta.inject.Singleton

class IpAuthorizationApprovedSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'IpAuthorizationApprovedSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.ip-patterns': ['10.10.0.48']
        ]
    }

    void "even if you are in the correct ip range, accessing the secured controller without authentication should return unauthorized"() {
        expect:
        applicationContext.containsBean(CustomAuthenticationProvider.class)

        when:
        HttpRequest req = HttpRequest.GET("/secured/authenticated")
                .accept(MediaType.TEXT_PLAIN)
                .basicAuth("user", "password")
        client.exchange(req, String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.FORBIDDEN
    }

    @Requires(property = 'spec.name', value = 'IpAuthorizationApprovedSpec')
    @Controller("/secured")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class SecuredController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/authenticated")
        String authenticated(Authentication authentication) {
            "${authentication.getName()} is authenticated"
        }
    }

    @Requires(property = 'spec.name', value = 'IpAuthorizationApprovedSpec')
    @Singleton
    static class CustomAuthenticationProvider implements AuthenticationProvider {
        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Flowable.create({emitter ->
                emitter.onNext(new UserDetails(authenticationRequest.identity as String, []))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
