package io.micronaut.security.authentication.provider

import groovy.transform.CompileStatic
import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.endpoints.LoginController
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "spec.name", value = "HttpRequestAuthenticationProviderAuthenticationExceptionSpec")
@Property(name = "micronaut.http.client.follow-redirects", value = StringUtils.FALSE)
@MicronautTest
class HttpRequestAuthenticationProviderAuthenticationExceptionSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    @Inject
    BeanContext beanContext

    void "login failure triggers redirect"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        HttpRequest<?> request = HttpRequest.POST("/login", new UsernamePasswordCredentials("sherlock", "foo"))

        expect:
        beanContext.containsBean(LoginController.class)

        when:
        HttpResponse<?> response = client.exchange(request)

        then:
        "/login/authFailed" == response.getHeaders().get(HttpHeaders.LOCATION)
    }

    @Requires(property = "spec.name", value = "HttpRequestAuthenticationProviderAuthenticationExceptionSpec")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {

        @Override
        AuthenticationResponse authenticate(
                @Nullable HttpRequest<B> httpRequest,
                @NonNull AuthenticationRequest<String, String> authenticationRequest
        ) {
            if (authenticationRequest.identity == "sherlock" && authenticationRequest.secret == "password") {
                return AuthenticationResponse.success(authenticationRequest.getIdentity())
            }
            throw new AuthenticationException(AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH))
        }
    }

    @Requires(property = "spec.name", value = "HttpRequestAuthenticationProviderAuthenticationExceptionSpec")
    @CompileStatic
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller("/login")
    static class LoginAuthController {

        @Produces(MediaType.TEXT_HTML)
        @Get("/authFailed")
        String authFailed() {
            return "<!DOCTYPE html><html><head><title></title></head><body><h1>Authentication Failed</h1></body></html>";
        }
    }
}
