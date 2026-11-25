package io.micronaut.security.oauth2.endpoint;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.validator.TokenValidator;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The UserInfo endpoint of an OpenID provider accepts any access token the provider issued, regardless of the client
 * the token was issued to. Thus, {@code UserInfoClientTokenValidator} must not be registered unless the application
 * explicitly opts in via {@code micronaut.security.oauth2.userinfo.validator=true}.
 */
class UserInfoClientTokenValidatorDisabledByDefaultTest {
    private static final String OTHER_CLIENT_ACCESS_TOKEN = "access-token-issued-to-another-client-not-a-secret";

    @Test
    void userInfoTokenValidationIsNotEnabledByDefault() {
        Map<String, Object> authServerConfiguration = Map.of(
            "spec.name", "UserInfoClientTokenValidatorDisabledByDefaultTestAuthServer"
        );
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfiguration)) {
            OpenIdConfigurationController controller = authServer.getApplicationContext().getBean(OpenIdConfigurationController.class);
            controller.setUrl(authServer.getURL().toString());

            Map<String, Object> serverConfig = Map.of(
                "spec.name", "UserInfoClientTokenValidatorDisabledByDefaultTest",
                "micronaut.security.oauth2.clients.authserver.client-id", "test-client-id",
                "micronaut.security.oauth2.clients.authserver.client-secret", "test-client-secret-not-a-secret",
                "micronaut.security.oauth2.clients.authserver.openid.issuer", authServer.getURL().toString()
            );
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig)) {
                assertTrue(server.getApplicationContext().getBeansOfType(TokenValidator.class).stream()
                    .noneMatch(v -> v.getClass().getSimpleName().equals("UserInfoClientTokenValidator")));

                HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
                BlockingHttpClient client = httpClient.toBlocking();
                HttpRequest<?> request = HttpRequest.GET("/principal")
                    .bearerAuth(OTHER_CLIENT_ACCESS_TOKEN)
                    .accept(MediaType.TEXT_PLAIN);
                HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
                assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
                assertEquals(0, controller.userInfoRequests, "UserInfo endpoint must not be contacted when the validator is disabled");
            }
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorDisabledByDefaultTest")
    @Controller("/principal")
    static class EchoUserController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorDisabledByDefaultTestAuthServer")
    @Controller
    static class OpenIdConfigurationController {
        private String url;
        int userInfoRequests;

        void setUrl(String url) {
            this.url = url;
        }

        /**
         * Simulates a provider UserInfo endpoint: it accepts every access token the provider issued, no matter
         * which client the token was issued to.
         */
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> userinfo(@Header String authorization) {
            userInfoRequests++;
            if (authorization.equals("Bearer " + OTHER_CLIENT_ACCESS_TOKEN)) {
                return HttpResponse.ok(Map.of("sub", "user-of-another-client", "name", "Other Client User"));
            }
            return HttpResponse.unauthorized();
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String openIdConfiguration() {
            return """
                {
                    "issuer":"%s/",
                    "authorization_endpoint":"%s/authorize",
                    "token_endpoint":"%s/oauth/token",
                    "userinfo_endpoint":"%s/userinfo",
                    "jwks_uri":"%s/.well-known/jwks.json",
                    "response_types_supported":["code"],
                    "subject_types_supported":["public"],
                    "id_token_signing_alg_values_supported":["RS256"]
                }
                """.replace("%s", url);
        }
    }
}
