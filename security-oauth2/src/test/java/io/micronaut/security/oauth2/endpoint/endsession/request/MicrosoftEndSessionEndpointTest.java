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

class MicrosoftEndSessionEndpointTest {
    private static final String OPENID_CONFIG = """
 {
 "token_endpoint":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/oauth2/v2.0/token",
 "token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt","client_secret_basic"],
 "jwks_uri":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/discovery/v2.0/keys",
 "response_modes_supported":["query","fragment","form_post"],
 "subject_types_supported":["pairwise"],
 "id_token_signing_alg_values_supported":["RS256"],
 "response_types_supported":["code","id_token","code id_token","id_token token"],
 "scopes_supported":["openid","profile","email","offline_access"],
 "issuer":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/v2.0",
 "request_uri_parameter_supported":false,
 "userinfo_endpoint":"https://graph.microsoft.com/oidc/userinfo",
 "authorization_endpoint":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/oauth2/v2.0/authorize",
 "device_authorization_endpoint":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/oauth2/v2.0/devicecode",
 "http_logout_supported":true,
 "frontchannel_logout_supported":true,
 "end_session_endpoint":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/oauth2/v2.0/logout",
 "claims_supported":["sub","iss","cloud_instance_name","cloud_instance_host_name","cloud_graph_host_name","msgraph_host","aud","exp","iat","auth_time","acr","nonce","preferred_username","name","tid","ver","at_hash","c_hash","email"],
 "kerberos_endpoint":"https://login.microsoftonline.com/8177030d-4c56-3c4a-a111-15a102c55cba/kerberos",
 "tenant_region_scope":null,
 "cloud_instance_name":"microsoftonline.com",
 "cloud_graph_host_name":"graph.windows.net",
 "msgraph_host":"graph.microsoft.com",
 "rbac_url":"https://pas.windows.net"
 }""";

    @Test
    void oracleCloudConfigurationSupportsEndSession() {
        String nameQualifier = "microsoft";
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
                Map.of("spec.name", "MicrosoftEndSessionEndpointTestAuthServer"))) {
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class,
                    Map.of("spec.name", "MicrosoftEndSessionEndpointTest",
                            "micronaut.security.oauth2.clients." + nameQualifier + ".openid.issuer", authServer.getURL().toString(),
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-secret", "yyy",
                            "micronaut.security.oauth2.clients." + nameQualifier + ".client-id", "xxx"
                    ))) {
                var openIdClient = server.getApplicationContext().getBean(OpenIdClient.class, Qualifiers.byName(nameQualifier));
                assertTrue(openIdClient.supportsEndSession());
            }
        }
    }

    @Requires(property = "spec.name", value = "MicrosoftEndSessionEndpointTest")
    @Singleton
    @Replaces(AuthorizationServerResolver.class)
    static class AuthorizationServerResolverReplacement implements AuthorizationServerResolver {
        @Override
        public Optional<AuthorizationServer> resolve(String issuer) {
            return Optional.of(AuthorizationServer.MICROSOFT);
        }
    }

    @Requires(property = "spec.name", value = "MicrosoftEndSessionEndpointTestAuthServer")
    @Controller
    static class OpenidConfigurationController {
        @Get("/.well-known/openid-configuration")
        String index() {
            return OPENID_CONFIG;
        }
    }
}