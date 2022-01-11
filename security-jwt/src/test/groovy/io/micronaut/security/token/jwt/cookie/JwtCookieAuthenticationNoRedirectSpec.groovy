package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.annotation.Secured
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton
import java.security.Principal

class JwtCookieAuthenticationNoRedirectSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'JwtCookieAuthenticationNoRedirectSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                "micronaut.security.endpoints.logout.get-allowed": true,
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.enabled': false,
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    def "verify jwt cookie authentication works without redirection"() {
        when:
        HttpRequest request = HttpRequest.GET('/')
        HttpResponse<String> rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'foo', password: 'foo'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 200

        and: 'login fails, cookie is not set'
        !loginRsp.getHeaders().get('Set-Cookie')

        when:
        loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 200

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie
        cookie.contains('JWT=')
        cookie.contains('Path=/')

        when:
        String sessionId = cookie.substring('JWT='.size(), cookie.indexOf(';'))
        request = HttpRequest.GET('/').cookie(Cookie.of('JWT', sessionId))
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')


        when:
        HttpRequest<?> logoutRequest = HttpRequest.GET('/logout').cookie(Cookie.of('JWT', sessionId))
        HttpResponse<?> logoutRsp = client.exchange(logoutRequest)

        then:
        logoutRsp.status().code == 200

        when:
        List<String> cookieHeaders = logoutRsp.getHeaders().getAll("Set-Cookie")

        then:
        cookieHeaders.size() == 2
        cookieHeaders.get(0).containsIgnoreCase("JWT=")
        cookieHeaders.get(0).containsIgnoreCase("Max-Age=0")
        cookieHeaders.get(1).containsIgnoreCase("JWT_REFRESH_TOKEN=")
        cookieHeaders.get(1).containsIgnoreCase("Max-Age=0")

        when:
        rsp = client.exchange(HttpRequest.GET('/'), String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationNoRedirectSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationNoRedirectSpec")
    @Secured("isAnonymous()")
    @Controller("/")
    static class HomeController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(@Nullable Principal principal) {
            return principal?.name ?: 'You are not logged in'
        }
    }
}
