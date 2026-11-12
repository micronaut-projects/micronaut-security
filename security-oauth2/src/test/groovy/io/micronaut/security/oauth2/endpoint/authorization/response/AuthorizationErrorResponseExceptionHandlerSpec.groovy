package io.micronaut.security.oauth2.endpoint.authorization.response

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.errors.ErrorCode
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification

class AuthorizationErrorResponseExceptionHandlerSpec extends Specification {

    void "OAuth 2.0 cancel redirects to login failed"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.security.redirect.login-failure': '/login/failed',
                'spec.name': "AuthorizationErrorResponseExceptionHandlerSpec"
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/throw/html")
                .accept(MediaType.TEXT_HTML), String)

        then:
        HttpStatus.OK == response.status()

        when:
        Optional<String> html = response.getBody()

        then:
        html.isPresent()
        html.get().contains("Login Failed")

        cleanup:
        client.close()
        httpClient.close()
        applicationContext.close()
        embeddedServer.close()
    }

    void "OAuth 2.0 does not redirect if redirection is disabled"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.security.redirect.login-failure': '/login/failed',
                'micronaut.security.redirect.enabled'      : StringUtils.FALSE,
                'spec.name'                                : "AuthorizationErrorResponseExceptionHandlerSpec"
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        client.exchange(HttpRequest.GET("/throw/html").accept(MediaType.TEXT_HTML))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.BAD_REQUEST == e.status

        cleanup:
        client.close()
        httpClient.close()
        applicationContext.close()
        embeddedServer.close()
    }

    void "does not redirect for non HTML requests"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'micronaut.security.redirect.login-failure': '/login/failed',
                'spec.name': "AuthorizationErrorResponseExceptionHandlerSpec"
        ])
        ApplicationContext applicationContext = embeddedServer.applicationContext
        HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        client.exchange(HttpRequest.GET("/throw/json"))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.BAD_REQUEST == e.status


        cleanup:
        client.close()
        httpClient.close()
        applicationContext.close()
        embeddedServer.close()
    }

    @Requires(property = "spec.name", value = "AuthorizationErrorResponseExceptionHandlerSpec")
    @Controller("/login")
    static class LoginFailedController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get("/failed")
        String index() {
            return "<!DOCTYPE html><html><head><title>Home</title></head><body><h1>Login Failed</h1></body> </html>";
        }
    }

    @Requires(property = "spec.name", value = "AuthorizationErrorResponseExceptionHandlerSpec")
    @Controller("/throw")
    static class ThrowingController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/json")
        String json() {
            throw createException()
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get("/html")
        String html() {
            throw createException()
        }

        private static AuthorizationErrorResponseException createException() {
            new AuthorizationErrorResponseException(new AuthorizationErrorResponse() {
                @Override
                State getState() {
                    return null
                }

                @Override
                ErrorCode getError() {
                    return new ErrorCode() {
                        @Override
                        String getErrorCode() {
                            return "user_cancelled_login"
                        }

                        @Override
                        String getErrorCodeDescription() {
                            return "The user cancelled LinkedIn login"
                        }
                    }
                }

                @Override
                String getErrorDescription() {
                    return "The user cancelled LinkedIn login"
                }

                @Override
                String getErrorUri() {
                    return null
                }
            })
        }
    }
}
