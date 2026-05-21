package io.micronaut.security.oauth2.configuration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;

class OauthConfigurationPropertiesSchemaTest {
    private static final String CLIENT = "io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties";
    private static final String CLIENT_CREDENTIALS = CLIENT + "$ClientCredentialsConfigurationProperties";
    private static final String OPENID_CLIENT = CLIENT + "$OpenIdClientConfigurationProperties";
    private static final String OAUTH = "io.micronaut.security.oauth2.configuration.OauthConfigurationProperties";
    private static final String OPENID = OAUTH + "$OpenIdConfigurationProperties";
    private static final String PKCE_COOKIE =
        "io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie.CookiePkcePersistenceConfiguration";
    private static final String STATE_COOKIE =
        "io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie.CookieStatePersistenceConfiguration";

    @Test
    void generatedConfigurationSchemasContainDefaults() throws IOException {
        assertDefaults(CLIENT, Map.of(
            "proxy-well-known-oauth-authorization-server", false,
            "proxy-well-known-openid-configuration", false,
            "enabled", true,
            "grant-type", "authorization_code"
        ));
        assertDefaults(CLIENT_CREDENTIALS, Map.of(
            "advanced-expiration", "30",
            "enabled", true
        ));
        assertDefaults(CLIENT_CREDENTIALS + "$HeaderTokenPropagatorConfigurationProperties", Map.of(
            "enabled", true,
            "prefix", "Bearer",
            "header-name", "Authorization"
        ));
        assertDefaults(CLIENT + "$TokenEndpointConfigurationProperties", Map.of(
            "authentication-method", "client_secret_basic"
        ));
        assertDefaults(CLIENT + "$IntrospectionEndpointConfigurationProperties", Map.of(
            "authentication-method", "client_secret_basic"
        ));
        assertDefaults(CLIENT + "$RevocationEndpointConfigurationProperties", Map.of(
            "authentication-method", "client_secret_basic"
        ));
        assertDefaults(OPENID_CLIENT, Map.of(
            "protected-resource-metadata", true,
            "configuration-path", "/.well-known/openid-configuration"
        ));
        assertDefaults(OPENID_CLIENT + "$AuthorizationEndpointConfigurationProperties", Map.of("response-type", "code"));
        assertDefaults(OPENID_CLIENT + "$TokenEndpointConfigurationProperties", Map.of(
            "authentication-method", "client_secret_basic",
            "content-type", "application/x-www-form-urlencoded"
        ));
        assertDefaults(OPENID_CLIENT + "$EndSessionConfigurationProperties", Map.of("enabled", true));
        assertDefaults(OAUTH, Map.of(
            "enabled", true,
            "login-uri", "/oauth/login{/provider}",
            "callback-uri", "/oauth/callback{/provider}"
        ));
        assertDefaults(OPENID, Map.of(
            "logout-uri", "/oauth/logout"
        ));
        assertDefaults(OPENID + "$EndSessionConfigurationProperties", Map.of("redirect-uri", "/logout"));
        assertDefaults(OPENID + "$ClaimsValidationConfigurationProperties", Map.of(
            "issuer", true,
            "audience", true,
            "authorized-party", true
        ));
        assertDefaults(OPENID + "$AdditionalClaimsConfigurationProperties", Map.of(
            "jwt", false,
            "access-token", false,
            "refresh-token", false
        ));
        assertDefaults("io.micronaut.security.oauth2.endpoint.authorization.pkce.PkceConfigurationProperties", Map.of(
            "entropy", 64,
            "persistence", "cookie",
            "enabled", true
        ));
        assertDefaults(PKCE_COOKIE, Map.of(
            "session-cookie", false,
            "cookie-name", "OAUTH2_PKCE",
            "cookie-path", "/",
            "cookie-http-only", true,
            "cookie-max-age", "300"
        ));
        assertDefaults("io.micronaut.security.oauth2.endpoint.authorization.state.DefaultStateConfiguration", Map.of(
            "persistence", "cookie",
            "enabled", true
        ));
        assertDefaults(STATE_COOKIE, Map.of(
            "session-cookie", false,
            "cookie-name", "OAUTH2_STATE",
            "cookie-path", "/",
            "cookie-http-only", true,
            "cookie-max-age", "300"
        ));
        assertDefaults("io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration", Map.of(
            "persistence", "cookie",
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie.CookieNoncePersistenceConfiguration", Map.of(
            "session-cookie", false,
            "cookie-name", "OPENID_NONCE",
            "cookie-path", "/",
            "cookie-http-only", true,
            "cookie-max-age", "300"
        ));
        assertDefaults("io.micronaut.security.oauth2.metadata.ProtectedResourceMetadataConfigurationProperties", Map.of(
            "enabled", true
        ));
    }
}
