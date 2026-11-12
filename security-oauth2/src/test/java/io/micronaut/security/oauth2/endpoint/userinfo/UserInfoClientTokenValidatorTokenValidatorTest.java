package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserInfoClientTokenValidatorTokenValidatorTest {
    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void userInfoClientTokenValidator(boolean userInfoOpenIdConfiguration) {

        Map<String, Object> authServerConfiguration = Map.of(
            "spec.name", "UserInfoClientTokenValidatorTestAuthServer"
        );
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfiguration)) {
            OpenIdAutoConfigurationController controller = authServer.getApplicationContext().getBean(OpenIdAutoConfigurationController.class);
            controller.setUrl(authServer.getURL().toString());
            controller.setUserInfoOpenIdConfiguration(userInfoOpenIdConfiguration);

            Map<String, Object> serverConfig = new HashMap<>(Map.of(
                "spec.name", "UserInfoClientTokenValidatorTest",
                "micronaut.security.oauth2.clients.authserver.client-id", "XXX",
                "micronaut.security.oauth2.clients.authserver.client-secret", "YYY",
                "micronaut.security.oauth2.clients.authserver.openid.issuer", authServer.getURL().toString()
            ));
            if (userInfoOpenIdConfiguration) {
                serverConfig.put("micronaut.security.oauth2.clients.authserver.openid.user-info.url", authServer.getURL().toString() + "/userinfo");
            }
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig)) {
                assertValidatorsOrder(server);
                UserInfoClientTokenValidator validator = server.getApplicationContext().getBean(UserInfoClientTokenValidator.class);
                assertEquals("authserver", validator.getName());
                HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
                BlockingHttpClient client = httpClient.toBlocking();
                HttpRequest<?> request = HttpRequest.GET("/principal")
                    .bearerAuth("xxx.yyy.zzz")
                    .accept(MediaType.TEXT_PLAIN);
                String username = assertDoesNotThrow(() -> client.retrieve(request));
                assertEquals("123baba456909", username);

                HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                    () -> client.retrieve(HttpRequest.GET("/principal").accept(MediaType.TEXT_PLAIN)));
                assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            }
        }
    }

    private static void assertValidatorsOrder(EmbeddedServer server) {
        List<TokenValidator> validators = new ArrayList<>(server.getApplicationContext().getBeansOfType(TokenValidator.class));
        assertTrue(CollectionUtils.isNotEmpty(validators));
        assertEquals(2, validators.size());
        int jsonWebTokenValidatorIndex = -1;
        int userInfoClientTokenValidatorIndex = -1;
        for (int i = 0; i < validators.size(); i++) {
            TokenValidator validator = validators.get(i);
            if (validator.getClass().getSimpleName().equals("NimbusReactiveJsonWebTokenValidator")) {
                jsonWebTokenValidatorIndex = i;
            } else if (validator instanceof UserInfoClientTokenValidator) {
                userInfoClientTokenValidatorIndex = i;
            }
        }
        assertTrue(jsonWebTokenValidatorIndex != -1, "JsonWebTokenValidator not found");
        assertTrue(userInfoClientTokenValidatorIndex != -1, "UserInfoClientTokenValidator not found");
        assertTrue(userInfoClientTokenValidatorIndex > jsonWebTokenValidatorIndex, "UserInfoClientTokenValidator should appear after JsonWebTokenValidator");
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorTest")
    @Controller("/principal")
    static class EchoUserController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorTestAuthServer")
    @Controller
    static class UserInfoController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> info(@Header String authorization) {
            if (authorization.equals("Bearer xxx.yyy.zzz")) {
                return HttpResponse.ok(Map.of(
                    "sub", "123baba456909",
                    "nickname", "mn",
                    "name", "Micronaut User",
                    "updated_at", "2025-09-17T17:12:41.152Z",
                    "email", "info@micronaut.io",
                    "email_verified", "true"));
            }
            return HttpResponse.unauthorized();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorTestAuthServer")
    @Controller
    static class OpenIdAutoConfigurationController {
        private String url;
        private boolean userInfoOpenIdConfiguration;

        public void setUserInfoOpenIdConfiguration(boolean userInfoOpenIdConfiguration) {
            this.userInfoOpenIdConfiguration = userInfoOpenIdConfiguration;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String index() {
            String json = """
                {
                    "issuer":"%s/",
                    "authorization_endpoint":"%s/authorize",
                    "token_endpoint":"%s/oauth/token",
                    "device_authorization_endpoint":"%s/oauth/device/code",
                    %userinfo
                    "mfa_challenge_endpoint":"%s/mfa/challenge",
                    "jwks_uri":"%s/.well-known/jwks.json",
                    "registration_endpoint":"%s/oidc/register",
                    "revocation_endpoint":"%s/oauth/revoke",
                    "scopes_supported":["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"],
                    "response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token"],
                    "code_challenge_methods_supported":["S256","plain"],
                    "response_modes_supported":["query","fragment","form_post"],
                    "subject_types_supported":["public"],
                    "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],
                    "token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","PS256"],
                    "claims_supported":["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"],
                    "request_uri_parameter_supported":false,
                    "request_parameter_supported":true,"id_token_signing_alg_values_supported":["HS256","RS256","PS256"],
                    "tls_client_certificate_bound_access_tokens":true,
                    "request_object_signing_alg_values_supported":["RS256","RS384","PS256"],
                    "backchannel_logout_supported":true,
                    "backchannel_logout_session_supported":true,
                    "end_session_endpoint":"%s/oidc/logout",
                    "backchannel_authentication_endpoint":"%s/bc-authorize",
                    "backchannel_token_delivery_modes_supported":["poll"],
                    "global_token_revocation_endpoint":"%s/oauth/global-token-revocation/connection/{connectionName}",
                    "global_token_revocation_endpoint_auth_methods_supported":["global-token-revocation+jwt"]
                }
                """.replace("%s", url);
            if (userInfoOpenIdConfiguration) {
                return json.replace("%userinfo", "");
            }
            return json.replace("%userinfo", "\"userinfo_endpoint\":\"%s/userinfo\",".replace("%s", url));
        }
    }
}
