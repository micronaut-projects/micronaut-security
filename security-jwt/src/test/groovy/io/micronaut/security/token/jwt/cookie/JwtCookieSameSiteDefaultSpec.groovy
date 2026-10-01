package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import org.reactivestreams.Publisher
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

class JwtCookieSameSiteDefaultSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'JwtCookieSameSiteDefaultSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration +
                [
                        'micronaut.http.client.followRedirects': false,
                        'micronaut.security.authentication': 'cookie',
                        'micronaut.security.token.cookie.cookie-max-age': '5m',
                        'micronaut.security.redirect.login-failure': '/login/authFailed',
                        'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                        'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                ]
    }

    void "JWT and refresh token cookies default to SameSite=Lax"() {
        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
        HttpResponse loginRsp = client.exchange(loginRequest, String)

        then:
        noExceptionThrown()

        when:
        List<String> cookies = loginRsp.getHeaders().getAll('Set-Cookie')

        then:
        cookies.size() == 2
        cookies[0].contains('JWT=')
        cookies[0].contains('SameSite=Lax')
        cookies[0].contains('HTTPOnly')
        cookies[1].contains('JWT_REFRESH_TOKEN=')
        cookies[1].contains('SameSite=Lax')
        cookies[1].contains('HTTPOnly')
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteDefaultSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider  {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( "sherlock")])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieSameSiteDefaultSpec")
    @Singleton
    static class TestRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, Authentication> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getAuthentication())
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }
}
