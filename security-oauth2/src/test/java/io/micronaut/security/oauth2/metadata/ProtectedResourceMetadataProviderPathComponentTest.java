package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.ApplicationConfiguration;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import jakarta.inject.Singleton;
import org.json.JSONException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtectedResourceMetadataProviderPathComponentTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "/.well-known/oauth-protected-resource/foo/bar"
    })
    void testProtectedResourceMetadataController(String path) throws JSONException {
        Map<String, Object> configuration = Map.of(
            "micronaut.application.name", "demo",
            "spec.name", "ProtectedResourceMetadataProviderPathComponentTest",
            "micronaut.security.oauth2.clients.oci.openid.issuer", "https://idcs-abcde.identity.oraclecloud.com");
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        String expected = String.format("""
              {
               "resource": "%s",
               "resource_name": "demo",
               "scopes_supported": ["foo","bar"],
               "authorization_servers": ["https://idcs-abcde.identity.oraclecloud.com"]
              }
            """, server.getURL().toString() + path.replace("/.well-known/oauth-protected-resource", ""));
        String json = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET(path)));
        JSONAssert.assertEquals(json, expected, json, true);
        client.close();
        httpClient.close();
        server.close();
    }

    @Requires(property = "spec.name", value = "ProtectedResourceMetadataProviderPathComponentTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class ProtectedResourceMetadataProviderMock extends DefaultProtectedResourceMetadataProvider {

        ProtectedResourceMetadataProviderMock(ApplicationConfiguration applicationConfiguration, HttpHostResolver httpHostResolver, List<OpenIdClientConfiguration> openIdClients) {
            super(applicationConfiguration, httpHostResolver, openIdClients);
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
            assertTrue(path.startsWith("/"));
            return builder(path, request)
                .scopesSupported(Arrays.stream(path.split("/")).filter(StringUtils::isNotEmpty).toList())
                .build();
        }
    }
}
