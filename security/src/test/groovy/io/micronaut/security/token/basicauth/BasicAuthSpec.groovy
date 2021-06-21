package io.micronaut.security.token.basicauth

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import io.micronaut.security.authentication.UserDetails
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class BasicAuthSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'BasicAuthSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
        ]
    }

    void "test /beans is not accessible if you don't supply Basic Auth in HTTP Header Authorization"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String path = "/beans"
        client.exchange(HttpRequest.GET(path), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test /beans is not accesible if you don't supply a valid Base64 encoded token in the Basic Auth in HTTP Header Authorization"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'Basic'
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test /beans is secured but accesible if you supply valid credentials with Basic Auth"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'dXNlcjpwYXNzd29yZA==' // user:passsword Base64
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        noExceptionThrown()
    }

    void "test /beans is not accessible if you valid Base64 encoded token but authentication fails"() {
        expect:
        embeddedServer.applicationContext.getBean(BasicAuthAuthenticationFetcher.class)
        embeddedServer.applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        String token = 'dXNlcjp1c2Vy' // user:user Base64 encoded
        String path = "/beans"
        client.exchange(HttpRequest.GET(path).header("Authorization", "Basic ${token}".toString()), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'BasicAuthSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', []))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }


            }, BackpressureStrategy.ERROR)
        }
    }

}
