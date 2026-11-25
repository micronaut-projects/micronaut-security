package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies that the body of a failed token request is still readable as a {@link TokenErrorResponse} when the
 * authorization server answers with an error code which is not a {@link TokenError} constant.
 */
class TokenErrorResponseHttpClientTest {

    private static final String SPEC_NAME = "TokenErrorResponseHttpClientTest";

    private static EmbeddedServer authServer;
    private static HttpClient httpClient;

    @BeforeAll
    static void startAuthServer() {
        authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME));
        httpClient = authServer.getApplicationContext().createBean(HttpClient.class, authServer.getURL());
    }

    @AfterAll
    static void stopAuthServer() {
        httpClient.close();
        authServer.close();
    }

    @Test
    void modelledErrorCodeIsReadFromTheErrorResponseBody() {
        TokenErrorResponse body = tokenErrorResponse("/token/invalid-grant");

        assertEquals(TokenError.INVALID_GRANT, body.getError());
        assertEquals("invalid_grant", body.getErrorCode());
        assertEquals("The refresh token is expired", body.getErrorDescription());
    }

    @Test
    void unmodelledErrorCodeIsReadFromTheErrorResponseBody() {
        TokenErrorResponse body = tokenErrorResponse("/token/vendor");

        assertNull(body.getError());
        assertEquals("mfa_required", body.getErrorCode());
        assertEquals("Multifactor authentication required", body.getErrorDescription());
    }

    @Test
    void errorResponseBodyWithoutErrorCodeIsRead() {
        TokenErrorResponse body = tokenErrorResponse("/token/no-error");

        assertNull(body.getError());
        assertNull(body.getErrorCode());
        assertEquals("Something went wrong", body.getErrorDescription());
    }

    private static TokenErrorResponse tokenErrorResponse(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.GET(path);
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request, Argument.of(Map.class), Argument.of(TokenErrorResponse.class)));
        assertEquals(HttpStatus.BAD_REQUEST, e.getStatus());
        return e.getResponse().getBody(TokenErrorResponse.class).orElseThrow();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/token")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AuthServerController {

        @Get("/invalid-grant")
        @Produces(MediaType.APPLICATION_JSON)
        HttpResponse<String> invalidGrant() {
            return HttpResponse.badRequest("{\"error\":\"invalid_grant\",\"error_description\":\"The refresh token is expired\"}");
        }

        @Get("/vendor")
        @Produces(MediaType.APPLICATION_JSON)
        HttpResponse<String> vendor() {
            return HttpResponse.badRequest("{\"error\":\"mfa_required\",\"error_description\":\"Multifactor authentication required\"}");
        }

        @Get("/no-error")
        @Produces(MediaType.APPLICATION_JSON)
        HttpResponse<String> noError() {
            return HttpResponse.badRequest("{\"error_description\":\"Something went wrong\"}");
        }
    }
}
