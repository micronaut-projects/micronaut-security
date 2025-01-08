package io.micronaut.docs.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.session.SessionIdResolver
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

import java.security.Principal

class SessionAuthenticationNoRedirectSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'session',
                'micronaut.security.redirect.enabled': false,
                'spec.name': 'SessionAuthenticationNoRedirectSpec',
        ]
    }

    def "session based authentication works without redirection"() {
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
        cookie.contains('SESSION=')
        cookie.endsWith('; HTTPOnly')

        when:
        String sessionId = cookie.split(";")[0].split("=")[1]
        request = HttpRequest.GET('/').cookie(Cookie.of('SESSION', sessionId))
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')

        when:
        String sessionIdInResolver = client.retrieve(HttpRequest.GET('/session/id')
                .accept(MediaType.TEXT_PLAIN)
                .cookie(Cookie.of('SESSION', sessionId)))

        then:
        noExceptionThrown()
        sessionIdInResolver

        when:
        client.exchange(HttpRequest.GET('/session/id')
                .accept(MediaType.TEXT_PLAIN))

        then:
        HttpClientResponseException ex = thrown()
        HttpStatus.NOT_FOUND == ex.status

        when:
        HttpRequest logoutRequest = HttpRequest.POST('/logout', "").cookie(Cookie.of('SESSION', sessionId))
        HttpResponse<String> logoutRsp = client.exchange(logoutRequest, String)

        then:
        noExceptionThrown()
        logoutRsp.status().code == 200

        when:
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')
    }

    @Requires(property = "spec.name", value = "SessionAuthenticationNoRedirectSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "SessionAuthenticationNoRedirectSpec")
    @Secured("isAnonymous()")
    @Controller("/")
    static class HomeController {
        private final SessionIdResolver<HttpRequest<?>> sessionIdResolver

        HomeController(SessionIdResolver<HttpRequest<?>> sessionIdResolver) {
            this.sessionIdResolver = sessionIdResolver
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(@Nullable Principal principal) {
            return principal?.name ?: 'You are not logged in'
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/session/id")
        Optional<String> index(HttpRequest<?> request) {
            return sessionIdResolver.findSessionId(request)
        }
    }
}
