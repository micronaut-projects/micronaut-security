package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import org.json.JSONException;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DefaultProtectedResourceMetadataProviderTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/resource1",
        "/.well-known/oauth-protected-resource/foo/bar"
    })
    void testProtectedResourceMetadataController(String path) throws JSONException {
        Map<String, Object> configuration = Map.of(
            "spec.name", "DefaultProtectedResourceMetadataProviderTest",
            "micronaut.security.oauth2.clients.oci.openid.issuer", "https://idcs-abcde.identity.oraclecloud.com");
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        String expected = String.format("""
              {
               "resource": "%s",
               "authorization_servers": ["https://idcs-abcde.identity.oraclecloud.com"]
              }
            """, server.getURL().toString() + path.replace("/.well-known/oauth-protected-resource", ""));
        HttpResponse<String> resp = assertDoesNotThrow(() ->
            client.exchange(HttpRequest.GET(path), String.class));
        assertEquals(HttpStatus.OK, resp.getStatus());
        String json = resp.body();
        JSONAssert.assertEquals(expected, json, true);
        client.close();
        httpClient.close();
        server.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/resource1",
        "/.well-known/oauth-protected-resource/foo/bar"
    })
    void testProtectedResourceMetadataControllerWithDisabledOpenIdClient(String path) throws JSONException {
        Map<String, Object> configuration = Map.of(
            "spec.name", "DefaultProtectedResourceMetadataProviderTest",
            "micronaut.security.oauth2.clients.oci.openid.issuer", "https://idcs-abcde.identity.oraclecloud.com",
            "micronaut.security.oauth2.clients.notexposed.openid.issuer", "https://idcs-notexposed.identity.oraclecloud.com",
            "micronaut.security.oauth2.clients.notexposed.openid.protected-resource-metadata", StringUtils.FALSE
        );
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        String expected = String.format("""
              {
               "resource": "%s",
               "authorization_servers": ["https://idcs-abcde.identity.oraclecloud.com"]
              }
            """, server.getURL().toString() + path.replace("/.well-known/oauth-protected-resource", ""));
        String json = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET(path)));
        JSONAssert.assertEquals(expected, json, true);
        client.close();
        httpClient.close();
        server.close();
    }
}
