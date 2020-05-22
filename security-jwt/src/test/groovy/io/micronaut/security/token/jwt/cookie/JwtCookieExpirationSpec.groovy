package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class JwtCookieExpirationSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'JwtCookieExpirationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.http.client.followRedirects': false,
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': '/login/authFailed',
                'micronaut.security.token.jwt.generator.access-token.expiration': '500',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    void "test max-age is set from jwt generator settings"() {
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse loginRsp = client.exchange(loginRequest, String)

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie.contains('Max-Age=500')
    }

    @Requires(property = "spec.name", value = "JwtCookieExpirationSpec")
    @Singleton
    static class AuthenticationProviderUserPassword implements AuthenticationProvider  {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create( {emitter ->
                if ( authenticationRequest.getIdentity().equals("sherlock") &&
                        authenticationRequest.getSecret().equals("password") ) {
                    emitter.onNext(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
                    emitter.onComplete()
                } else {
                    emitter.onNext(new AuthenticationFailed())
                    emitter.onComplete()
                }
            }, BackpressureStrategy.ERROR)
        }
    }
}
