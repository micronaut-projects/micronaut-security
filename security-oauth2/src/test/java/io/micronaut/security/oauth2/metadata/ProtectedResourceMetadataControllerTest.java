package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class ProtectedResourceMetadataControllerTest {
    @Test
    void testProtectedResourceMetadataController() throws JSONException {
        Map<String, Object> configuration = Map.of("spec.name", "ProtectedResourceMetadataControllerTest");
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        String expected = String.format("""
              {
               "resource":
                 "%s",
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
            """, server.getURL().toString());
        String json = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET("/.well-known/oauth-protected-resource")));
        JSONAssert.assertEquals(expected, json, true);
    }

    @Requires(property = "spec.name", value = "ProtectedResourceMetadataControllerTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class ProtectedResourceMetadataProviderMock implements ProtectedResourceMetadataProvider<HttpRequest<?>> {
        private final HttpHostResolver httpHostResolver;

        ProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull HttpRequest<?> request) {
            String resource = httpHostResolver.resolve(request);
            List<String> authorizationServers = List.of("https://as1.example.com",
                "https://as2.example.net");
            List<String> scopesSupported = List.of("profile", "email", "phone");
            List<String> bearerMethodsSupported = List.of("header", "body");
            String resourceDocumentation = "https://resource.example.com/resource_documentation.html";
            return ProtectedResourceMetadata.builder().resource(resource)
                .authorizationServers(authorizationServers)
                .scopesSupported(scopesSupported)
                .bearerMethodsSupported(bearerMethodsSupported)
                .resourceDocumentation(resourceDocumentation)
                .build();
        }
    }
}
