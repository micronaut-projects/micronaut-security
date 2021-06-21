package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import jakarta.inject.Singleton;

class RefreshTokenIntrospectionEndpointSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'RefreshTokenIntrospectionEndpointSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }

    def "Token introspection endpoint can be use to check if a refresh token is active"() {
        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse loginRsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        loginRsp.status() == HttpStatus.OK
        loginRsp.body().refreshToken

        when:
        String refreshToken = loginRsp.body().refreshToken
        HttpRequest request = HttpRequest.POST("/token_info", new IntrospectionRequest(refreshToken))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth('user', 'password')
        HttpResponse<Map> response = client.exchange(request, Map)

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK

        when:
        Map m = response.body()

        then:
        m.keySet() == ['active'] as Set<String>
        m['active'] == true
    }

    @Requires(property = 'spec.name', value = 'RefreshTokenIntrospectionEndpointSpec')
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, UserDetails> tokens = [:]

        @Override
        void onApplicationEvent(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getUserDetails())
        }

        @Override
        Publisher<UserDetails> getUserDetails(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'RefreshTokenIntrospectionEndpointSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
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
