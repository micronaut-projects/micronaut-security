package io.micronaut.security.oauth2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CustomAuthMethodTest {

    @Disabled("https://github.com/micronaut-projects/micronaut-security/issues/1774")
    @Test
    void verifyCustomAuthMethodsAreSupported() {
        EmbeddedServer authserver = ApplicationContext.run(EmbeddedServer.class,
                Map.of(
                        "spec.name", "CustomAuthMethodTestAuthServer"
                ));
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class,
                Map.of(
                        "spec.name", "CustomAuthMethodTest",
                        "micronaut.security.oauth2.clients.authserver.openid.issuer", "http://localhost:" + authserver.getPort() + "/oauth2/default"
                ));
        OpenIdProviderMetadata openIdProviderMetadata = server.getApplicationContext().getBean(OpenIdProviderMetadata.class);
        assertNotNull(openIdProviderMetadata);
        openIdProviderMetadata.getTokenEndpointAuthMethods();
        authserver.close();
        server.close();
    }

    @Requires(property = "spec.name", value = "CustomAuthMethodTestAuthServer")
    @Controller("/oauth2/default")
    static class OpenIdConfigurationController {

        @Get("/.well-known/openid-configuration")
        @Secured(SecurityRule.IS_ANONYMOUS)
        String index() {
            return """
                      {
                      "issuer": "https://issuer",
                      "authorization_endpoint": "https://issuer/oauth/authorize",
                      "token_endpoint": "https://issuer/oauth/token",
                      "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                        "client_secret_jwt",
                        "private_key_jwt",
                        "tls_client_auth",
                        "self_signed_tls_client_auth"
                      ],
                      "jwks_uri": "https://issuer/.well-known/jwks.json",
                      "userinfo_endpoint": "https://issuer/api/v1/openid/userinfo",
                      "response_types_supported": [
                        "code"
                      ],
                      "grant_types_supported": [
                        "authorization_code"
                      ],
                      "code_challenge_methods_supported": [
                        "S256"
                      ],
                      "tls_client_certificate_bound_access_tokens": true,
                      "subject_types_supported": [
                        "public"
                      ],
                      "id_token_signing_alg_values_supported": [
                        "RS256"
                      ],
                      "scopes_supported": [
                        "openid",
                        "profile"
                      ],
                      "acr_values_supported": [
                        "-1",
                        "0",
                        "1",
                        "2",
                        "3"
                      ],
                      "display_values_supported": [
                        "page"
                      ]
                    }""";
        }
    }
}
