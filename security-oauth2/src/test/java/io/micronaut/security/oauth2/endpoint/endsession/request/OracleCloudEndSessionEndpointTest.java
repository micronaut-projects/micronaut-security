package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.client.OpenIdClient;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class OracleCloudEndSessionEndpointTest {
    private static final String OPENID_CONFIG = """
            {"issuer":"https://identity.oraclecloud.com/",
  "authorization_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/authorize",
  "token_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/token",
  "userinfo_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/userinfo",
  "revocation_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/revoke",
  "introspection_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/introspect",
  "end_session_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/oauth2/v1/userlogout",
  "secure_authorization_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/authorize",
  "secure_token_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/token",
  "secure_userinfo_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/userinfo",
  "secure_revocation_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/revoke",
  "secure_introspection_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/introspect",
  "secure_end_session_endpoint":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/oauth2/v1/userlogout",
  "jwks_uri":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com:443/admin/v1/SigningCert/jwk",
  "secure_jwks_uri":"https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.eu-madrid-idcs-1.secure.identity.oraclecloud.com/admin/v1/SigningCert/jwk",
  "scopes_supported":["openid", "profile", "offline_access", "email", "address", "phone", "groups", "get_groups", "approles", "get_approles"],
  "response_types_supported":["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
  "subject_types_supported":["public"],
  "id_token_signing_alg_values_supported":["RS256"],
  "claims_supported":["aud", "exp", "iat", "iss", "jti", "sub"],
  "grant_types_supported":["client_credentials", "password", "refresh_token", "authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer", "tls_cert_auth"],
  "token_endpoint_auth_methods_supported":["client_secret_basic", "private_key_jwt", "client_secret_post"],
  "token_endpoint_auth_signing_alg_values_supported":["RS256"],
  "userinfo_signing_alg_values_supported":["none"],
  "ui_locales_supported":["en"],
  "claims_parameter_supported":false,
  "http_logout_supported":true,
  "logout_session_supported":false,
  "request_parameter_supported":false,
  "request_uri_parameter_supported":false,
  "require_request_uri_registration":false,
  "idcs_id_token":"supported",
  "idcs_logout_v3":"supported"
}
            """;

    @Test
    void oracleCloudConfigurationSupportsEndSession() {
        String nameQualifier = "oci";
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
                Map.of("spec.name", "OracleCloudEndSessionEndpointTestAuthServer"))) {

            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class,
                    Map.of("spec.name", "OracleCloudEndSessionEndpointTest",
                            "micronaut.security.oauth2.clients." + nameQualifier + ".openid.issuer", authServer.getURL().toString(),
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-secret", "yyy",
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-id", "xxx"
                    ))) {

                OpenIdClient openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName(nameQualifier));
                assertTrue(openIdClient.supportsEndSession());
            }
        }
    }

    @Requires(property = "spec.name", value = "OracleCloudEndSessionEndpointTest")
    @Singleton
    @Replaces(AuthorizationServerResolver.class)
    static class AuthorizationServerResolverReplacement implements AuthorizationServerResolver {
        @Override
        public Optional<AuthorizationServer> resolve(String issuer) {
            return Optional.of(AuthorizationServer.ORACLE_CLOUD);
        }
    }

    @Requires(property = "spec.name", value = "OracleCloudEndSessionEndpointTestAuthServer")
    @Controller
    static class OpenidConfigurationController {
        @Get("/.well-known/openid-configuration")
        String index() {
            return OPENID_CONFIG;
        }
    }
}