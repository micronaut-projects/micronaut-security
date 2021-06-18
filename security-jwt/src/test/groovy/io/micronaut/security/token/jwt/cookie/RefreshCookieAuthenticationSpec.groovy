package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Specification

import jakarta.inject.Singleton

class RefreshCookieAuthenticationSpec extends Specification {

    void "test cookie authentication with refresh token defaults"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': getClass().simpleName,
            'micronaut.http.client.followRedirects': false,
            'micronaut.security.authentication': 'cookie',
            'micronaut.security.redirect.login-failure': '/login/authFailed',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
            'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne'
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        BlockingHttpClient client = applicationContext.createBean(HttpClient, embeddedServer.getURL()).toBlocking()


        when:
        MutableHttpRequest<LoginForm> loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        when:
        List<String> cookies = loginRsp.getHeaders().getAll("Set-Cookie")

        then:
        !cookies.isEmpty()

        cookies[0].contains('JWT=')

        cookies[1].contains('JWT_REFRESH_TOKEN=')
        cookies[1].contains('Path=/oauth/access_token')
        cookies[1].contains('Max-Age=2592000')
        cookies[1].contains('HTTPOnly')

        cleanup:
        applicationContext.close()
    }

    void "test cookie authentication with refresh token cookie configuration"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': getClass().simpleName,
                'micronaut.http.client.followRedirects': false,
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': '/login/authFailed',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.token.refresh.cookie.cookie-name': 'TEST',
                'micronaut.security.token.refresh.cookie.cookie-same-site': 'None',
                'micronaut.security.token.refresh.cookie.cookie-path': '/test',
                'micronaut.security.token.refresh.cookie.cookie-http-only': false,
                'micronaut.security.token.refresh.cookie.cookie-max-age': '10m',
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        BlockingHttpClient client = applicationContext.createBean(HttpClient, embeddedServer.getURL()).toBlocking()


        when:
        MutableHttpRequest<LoginForm> loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        when:
        List<String> cookies = loginRsp.getHeaders().getAll("Set-Cookie")

        then:
        !cookies.isEmpty()

        cookies[0].contains('JWT=')

        cookies[1].contains('TEST=')
        cookies[1].contains('Path=/test')
        cookies[1].contains('Max-Age=600')
        cookies[1].contains('SameSite=None')
        !cookies[1].contains('HTTPOnly')

        cleanup:
        applicationContext.close()
    }

    @Requires(property = "spec.name", value = "RefreshCookieAuthenticationSpec")
    @Singleton
    static class AuthenticationProviderUserPassword implements AuthenticationProvider  {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                if ( authenticationRequest.getIdentity().equals("sherlock") &&
                        authenticationRequest.getSecret().equals("password") ) {
                    emitter.onNext(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }
            }, BackpressureStrategy.ERROR)
        }
    }

    @Requires(property = "spec.name", value = "RefreshCookieAuthenticationSpec")
    @Singleton
    static class TestRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, UserDetails> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getUserDetails())
        }

        @Override
        Publisher<UserDetails> getUserDetails(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }
}
