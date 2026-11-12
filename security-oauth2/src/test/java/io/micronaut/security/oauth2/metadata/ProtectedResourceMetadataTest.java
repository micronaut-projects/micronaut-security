package io.micronaut.security.oauth2.metadata;

import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import io.micronaut.core.type.Argument;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

@MicronautTest(startApplication = false)
class ProtectedResourceMetadataTest {

    @Test
    void serializeProtectedResourceMetadata(JsonMapper jsonMapper) throws IOException, JSONException {
        String resource = "https://resource.example.com";
        List<String> authorizationServers = List.of("https://as1.example.com",
            "https://as2.example.net");
        String jwksUri = null;
        List<String> scopesSupported = List.of("profile", "email", "phone");
        List<String> bearerMethodsSupported = List.of("header", "body");
        List<String> resourceSigningAlgValuesSupported = null;
        String resourceName = null;
        String resourceDocumentation = "https://resource.example.com/resource_documentation.html";
        String resourcePolicyUri = null;
        String resourceTosUri = null;
        Boolean tlsClientCertificateBoundAccessTokens = null;
        List<String> authorizationDetailsTypesSupported = null;
        List<String> dpopSigningAlgValuesSupported = null;
        Boolean dpopBoundAccessTokensRequired = null;

        ProtectedResourceMetadata metadata = new ProtectedResourceMetadata(resource,
            authorizationServers,
            jwksUri,
            scopesSupported,
            bearerMethodsSupported,
            resourceSigningAlgValuesSupported,
            resourceName,
            resourceDocumentation,
            resourcePolicyUri,
            resourceTosUri,
            tlsClientCertificateBoundAccessTokens,
            authorizationDetailsTypesSupported,
            dpopSigningAlgValuesSupported,
            dpopBoundAccessTokensRequired);

        String expected = """
              {
               "resource":
                 "https://resource.example.com",
               "authorization_servers":
                 ["https://as1.example.com",
                  "https://as2.example.net"],
               "bearer_methods_supported":
                 ["header", "body"],
               "scopes_supported":
                 ["profile", "email", "phone"],
               "resource_documentation":
                 "https://resource.example.com/resource_documentation.html"
              }
            """;
        JSONAssert.assertEquals(expected, jsonMapper.writeValueAsString(metadata), true);

        metadata = ProtectedResourceMetadata.builder().resource(resource)
            .authorizationServers(authorizationServers)
            .scopesSupported(scopesSupported)
            .bearerMethodsSupported(bearerMethodsSupported)
            .resourceDocumentation(resourceDocumentation)
            .build();
        JSONAssert.assertEquals(expected, jsonMapper.writeValueAsString(metadata), true);
    }

    @Test
    void serializeAllProperties(JsonMapper jsonMapper) throws IOException, JSONException {
        ProtectedResourceMetadata metadata = ProtectedResourceMetadata.builder()
            .resource("https://api.example.com")
            .authorizationServers(List.of("https://as.example.com"))
            .jwksUri("https://api.example.com/jwks.json")
            .scopesSupported(List.of("read", "write"))
            .bearerMethodsSupported(List.of("header", "body", "query"))
            .resourceSigningAlgValuesSupported(List.of("RS256", "ES256"))
            .resourceName("Example API")
            .resourceDocumentation("https://api.example.com/docs")
            .resourcePolicyUri("https://api.example.com/policy")
            .resourceTosUri("https://api.example.com/tos")
            .tlsClientCertificateBoundAccessTokens(true)
            .authorizationDetailsTypesSupported(List.of("payment_initiation"))
            .dpopSigningAlgValuesSupported(List.of("ES256"))
            .dpopBoundAccessTokensRequired(true)
            .build();

        String expected = """
            {
              "resource": "https://api.example.com",
              "authorization_servers": ["https://as.example.com"],
              "jwks_uri": "https://api.example.com/jwks.json",
              "scopes_supported": ["read", "write"],
              "bearer_methods_supported": ["header", "body", "query"],
              "resource_signing_alg_values_supported": ["RS256", "ES256"],
              "resource_name": "Example API",
              "resource_documentation": "https://api.example.com/docs",
              "resource_policy_uri": "https://api.example.com/policy",
              "resource_tos_uri": "https://api.example.com/tos",
              "tls_client_certificate_bound_access_tokens": true,
              "authorization_details_types_supported": ["payment_initiation"],
              "dpop_signing_alg_values_supported": ["ES256"],
              "dpop_bound_access_tokens_required": true
            }
            """;

        JSONAssert.assertEquals(expected, jsonMapper.writeValueAsString(metadata), true);
    }

    @Test
    void serializeAllProperties_usesJsonPropertyNames(JsonMapper jsonMapper) throws IOException {
        ProtectedResourceMetadata metadata = ProtectedResourceMetadata.builder()
            .resource("https://api.example.com")
            .authorizationServers(List.of("https://as.example.com"))
            .jwksUri("https://api.example.com/jwks.json")
            .scopesSupported(List.of("read", "write"))
            .bearerMethodsSupported(List.of("header", "body", "query"))
            .resourceSigningAlgValuesSupported(List.of("RS256", "ES256"))
            .resourceName("Example API")
            .resourceDocumentation("https://api.example.com/docs")
            .resourcePolicyUri("https://api.example.com/policy")
            .resourceTosUri("https://api.example.com/tos")
            .tlsClientCertificateBoundAccessTokens(true)
            .authorizationDetailsTypesSupported(List.of("payment_initiation"))
            .dpopSigningAlgValuesSupported(List.of("ES256"))
            .dpopBoundAccessTokensRequired(true)
            .build();

        String json = jsonMapper.writeValueAsString(metadata);
        Map<String, Object> root = jsonMapper.readValue(json.getBytes(StandardCharsets.UTF_8), Argument.mapOf(String.class, Object.class));

        // Presence of expected snake_case keys
        assertTrue(root.containsKey("resource"));
        assertTrue(root.containsKey("authorization_servers"));
        assertTrue(root.containsKey("jwks_uri"));
        assertTrue(root.containsKey("scopes_supported"));
        assertTrue(root.containsKey("bearer_methods_supported"));
        assertTrue(root.containsKey("resource_signing_alg_values_supported"));
        assertTrue(root.containsKey("resource_name"));
        assertTrue(root.containsKey("resource_documentation"));
        assertTrue(root.containsKey("resource_policy_uri"));
        assertTrue(root.containsKey("resource_tos_uri"));
        assertTrue(root.containsKey("tls_client_certificate_bound_access_tokens"));
        assertTrue(root.containsKey("authorization_details_types_supported"));
        assertTrue(root.containsKey("dpop_signing_alg_values_supported"));
        assertTrue(root.containsKey("dpop_bound_access_tokens_required"));

        // Absence of camelCase keys
        assertFalse(root.containsKey("authorizationServers"));
        assertFalse(root.containsKey("jwksUri"));
        assertFalse(root.containsKey("scopesSupported"));
        assertFalse(root.containsKey("bearerMethodsSupported"));
        assertFalse(root.containsKey("resourceSigningAlgValuesSupported"));
        assertFalse(root.containsKey("resourceName"));
        assertFalse(root.containsKey("resourceDocumentation"));
        assertFalse(root.containsKey("resourcePolicyUri"));
        assertFalse(root.containsKey("resourceTosUri"));
        assertFalse(root.containsKey("tlsClientCertificateBoundAccessTokens"));
        assertFalse(root.containsKey("authorizationDetailsTypesSupported"));
        assertFalse(root.containsKey("dpopSigningAlgValuesSupported"));
        assertFalse(root.containsKey("dpopBoundAccessTokensRequired"));
    }
}
