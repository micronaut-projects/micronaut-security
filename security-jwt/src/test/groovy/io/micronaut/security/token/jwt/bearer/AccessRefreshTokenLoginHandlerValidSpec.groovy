package io.micronaut.security.token.jwt.bearer

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class AccessRefreshTokenLoginHandlerValidSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'AccessRefreshTokenLoginHandlerValidSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    void "test valid authentication"() {
        when:
        def creds = new UsernamePasswordCredentials("valid", "valid")
        def resp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        resp.status == HttpStatus.OK
        resp.body().accessToken
        !resp.body().refreshToken
        resp.body().username == "valid"
        resp.body().roles == ["foo", "bar"]
        resp.body().expiresIn

        when: 'validate json response contains access_token and refresh_token keys as described in RFC6759'
        String json = client.retrieve(HttpRequest.POST('/login', creds), String)

        then:
        json.contains('access_token')
        !json.contains('refresh_token')
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'AccessRefreshTokenLoginHandlerValidSpec')
    static class TestingAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                emitter.onNext(new UserDetails(authenticationRequest.identity as String, ["foo", "bar"]))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
