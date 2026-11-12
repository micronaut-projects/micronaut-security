package io.micronaut.security.oauth2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class WellKnownProxyFilterTest {
    private static final String OPENID_AUTO_CONFIGURATION = """
        {"issuer":"https://auth.example.com/","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/oauth/token","device_authorization_endpoint":"https://auth.example.com/oauth/device/code","userinfo_endpoint":"https://auth.example.com/userinfo","mfa_challenge_endpoint":"https://auth.example.com/mfa/challenge","jwks_uri":"https://auth.example.com/.well-known/jwks.json","registration_endpoint":"https://auth.example.com/oidc/register","revocation_endpoint":"https://auth.example.com/oauth/revoke","scopes_supported":["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"],"response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token"],"code_challenge_methods_supported":["S256","plain"],"response_modes_supported":["query","fragment","form_post"],"subject_types_supported":["public"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","PS256"],"claims_supported":["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"],"request_uri_parameter_supported":false,"request_parameter_supported":true,"id_token_signing_alg_values_supported":["HS256","RS256","PS256"],"tls_client_certificate_bound_access_tokens":true,"request_object_signing_alg_values_supported":["RS256","RS384","PS256"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"end_session_endpoint":"https://auth.example.com/oidc/logout","backchannel_authentication_endpoint":"https://auth.example.com/bc-authorize","backchannel_token_delivery_modes_supported":["poll"],"global_token_revocation_endpoint":"https://auth.example.com/oauth/global-token-revocation/connection/{connectionName}","global_token_revocation_endpoint_auth_methods_supported":["global-token-revocation+jwt"]}
        """;

    private static final String OAUTH_AUTHORIZATION_SERVER = """
        {"issuer":"https://auth.example.com/","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/oauth/token","device_authorization_endpoint":"https://auth.example.com/oauth/device/code","userinfo_endpoint":"https://auth.example.com/userinfo","mfa_challenge_endpoint":"https://auth.example.com/mfa/challenge","jwks_uri":"https://auth.example.com/.well-known/jwks.json","registration_endpoint":"https://auth.example.com/oidc/register","revocation_endpoint":"https://auth.example.com/oauth/revoke","scopes_supported":["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"],"response_types_supported":["code","token","id_token","code token","code id_token","token id_token","code token id_token"],"code_challenge_methods_supported":["S256","plain"],"response_modes_supported":["query","fragment","form_post"],"subject_types_supported":["public"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","PS256"],"claims_supported":["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"],"request_uri_parameter_supported":false,"request_parameter_supported":true,"id_token_signing_alg_values_supported":["HS256","RS256","PS256"],"tls_client_certificate_bound_access_tokens":true,"request_object_signing_alg_values_supported":["RS256","RS384","PS256"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"end_session_endpoint":"https://auth.example.com/oidc/logout","backchannel_authentication_endpoint":"https://auth.example.com/bc-authorize","backchannel_token_delivery_modes_supported":["poll"],"global_token_revocation_endpoint":"https://auth.example.com/oauth/global-token-revocation/connection/{connectionName}","global_token_revocation_endpoint_auth_methods_supported":["global-token-revocation+jwt"]}
        """;

    @Test
    void userInfoClientTokenValidator() {
        Map<String, Object> authServerConfiguration = Map.of(
            "spec.name", "WellKnownProxyFilterTestAuthServer"
        );
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfiguration)) {
            Map<String, Object> serverConfig = new HashMap<>(Map.of(
                "spec.name", "WellKnownProxyFilterTest",
                "micronaut.security.oauth2.clients.authserver.client-id", "XXX",
                "micronaut.security.oauth2.clients.authserver.client-secret", "YYY",
                "micronaut.security.oauth2.clients.authserver.proxy-well-known-oauth-authorization-server", StringUtils.TRUE,
                "micronaut.security.oauth2.clients.authserver.proxy-well-known-openid-configuration", StringUtils.TRUE,
                "micronaut.security.oauth2.clients.authserver.openid.issuer", authServer.getURL().toString()
            ));
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig)) {
                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    BlockingHttpClient client = httpClient.toBlocking();
                    HttpRequest<?> oauthAuthorizationServerRequest = HttpRequest.GET("/.well-known/oauth-authorization-server");
                    String oauthAuthorizationServerRequestJson = assertDoesNotThrow(() -> client.retrieve(oauthAuthorizationServerRequest));
                    assertEquals(OPENID_AUTO_CONFIGURATION, oauthAuthorizationServerRequestJson);

                    HttpRequest<?> openidAutoconfigurationRequest = HttpRequest.GET("/.well-known/openid-configuration");
                    String openidAutoconfigurationRequestJson = assertDoesNotThrow(() -> client.retrieve(openidAutoconfigurationRequest));
                    assertEquals(OPENID_AUTO_CONFIGURATION, openidAutoconfigurationRequestJson);
                }
            }
        }
    }

    @Requires(property = "spec.name", value = "WellKnownProxyFilterTestAuthServer")
    @Controller
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AuthServerController {
        @Get("/.well-known/oauth-authorization-server")
        String oauthAuthorizationServer() {
            return OAUTH_AUTHORIZATION_SERVER;
        }

        @Get("/.well-known/openid-configuration")
        String openIdConfiguration() {
            return OPENID_AUTO_CONFIGURATION;
        }
    }
}
