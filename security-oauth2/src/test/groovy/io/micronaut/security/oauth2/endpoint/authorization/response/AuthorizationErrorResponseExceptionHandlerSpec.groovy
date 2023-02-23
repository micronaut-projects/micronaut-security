package io.micronaut.security.oauth2.endpoint.authorization.response

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.errors.ErrorCode
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification

class AuthorizationErrorResponseExceptionHandlerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        return "AuthorizationErrorResponseExceptionHandlerSpec"
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.redirect.login-failure': '/login/failed'
        ]
    }

    void "OAuth 2.0 cancel redirects to login failed"() {
        given:
        HttpRequest<?> request = HttpRequest.GET("/throw").accept(MediaType.TEXT_HTML)

        when:
        String html = client.retrieve(request)

        then:
        html.contains("Login Failed")
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
        @Produces(MediaType.TEXT_HTML)
        @Get
        String index() {
            throw new AuthorizationErrorResponseException(new AuthorizationErrorResponse() {
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
