package io.micronaut.security;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static java.util.Map.entry;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;

class ConfigurationPropertiesSchemaTest {
    @Test
    void generatedConfigurationSchemasContainDefaults() throws IOException {
        assertDefaults("io.micronaut.security.authentication.BasicAuthAuthenticationConfiguration", Map.of(
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.config.RedirectConfigurationProperties", Map.of(
            "login-success", "/",
            "login-failure", "/",
            "logout", "/",
            "prior-to-login", false,
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.config.RedirectConfigurationProperties$UnauthorizedRedirectConfigurationProperties", Map.of(
            "url", "/",
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.config.RedirectConfigurationProperties$ForbiddenRedirectConfigurationProperties", Map.of(
            "url", "/",
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.config.RedirectConfigurationProperties$RefreshRedirectConfigurationProperties", Map.of(
            "url", "/",
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.config.SecurityConfigurationProperties", Map.of(
            "enabled", true,
            "ip-patterns", "0.0.0.0",
            "intercept-url-map-prepend-pattern-with-context-path", true,
            "authentication-provider-strategy", "ANY",
            "reject-not-found", true
        ));
        assertDefaults("io.micronaut.security.endpoints.LoginControllerConfigurationProperties", Map.of(
            "post-content-types", "application/json,application/x-www-form-urlencoded",
            "unsupported-post-content-type-status", 404,
            "enabled", true,
            "path", "/login"
        ));
        assertDefaults("io.micronaut.security.endpoints.LogoutControllerConfigurationProperties", Map.ofEntries(
            entry("post-content-types", "application/json,application/x-www-form-urlencoded"),
            entry("unsupported-post-content-type-status", 404),
            entry("enabled", true),
            entry("path", "/logout"),
            entry("get-allowed", false)
        ));
        assertDefaults("io.micronaut.security.endpoints.OauthControllerConfigurationProperties", Map.ofEntries(
            entry("post-content-types", "application/json,application/x-www-form-urlencoded"),
            entry("unsupported-post-content-type-status", 404),
            entry("enabled", true),
            entry("path", "/oauth/access_token"),
            entry("get-allowed", true)
        ));
        assertDefaults("io.micronaut.security.endpoints.introspection.IntrospectionConfigurationProperties", Map.of(
            "enabled", true,
            "path", "/token_info"
        ));
        assertDefaults("io.micronaut.security.filters.SecurityFilterConfigurationProperties", Map.of(
            "enabled", true,
            "path", "/**"
        ));
        assertDefaults("io.micronaut.security.token.bearer.BearerTokenConfigurationProperties", Map.of(
            "enabled", true,
            "prefix", "Bearer",
            "header-name", "Authorization"
        ));
        assertDefaults("io.micronaut.security.token.config.TokenConfigurationProperties", Map.of(
            "enabled", true,
            "roles-name", "roles",
            "name-key", "sub"
        ));
        assertDefaults("io.micronaut.security.token.cookie.TokenCookieConfigurationProperties", Map.of(
            "session-cookie", false,
            "cookie-http-only", true,
            "enabled", true,
            "cookie-name", "JWT",
            "cookie-path", "/"
        ));
        assertDefaults("io.micronaut.security.token.cookie.RefreshTokenCookieConfigurationProperties", Map.of(
            "session-cookie", false,
            "cookie-http-only", true,
            "enabled", true,
            "cookie-name", "JWT_REFRESH_TOKEN",
            "cookie-path", "/oauth/access_token"
        ));
        assertDefaults("io.micronaut.security.token.generator.AccessTokenConfigurationProperties", Map.of(
            "expiration", 3600
        ));
        assertDefaults("io.micronaut.security.token.propagation.TokenPropagationConfigurationProperties", Map.of(
            "enabled", false,
            "path", "/**"
        ));
        assertDefaults("io.micronaut.security.token.propagation.HttpHeaderTokenPropagatorConfigurationProperties", Map.of(
            "enabled", true,
            "prefix", "Bearer",
            "header-name", "Authorization"
        ));
        assertDefaults("io.micronaut.security.x509.X509ConfigurationProperties", Map.of(
            "subject-dn-regex", "CN=(.*?)(?:,|$)",
            "enabled", false
        ));
    }
}
