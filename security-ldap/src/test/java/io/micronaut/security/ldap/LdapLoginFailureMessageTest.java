package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.authentication=bearer}, a failed POST /login carries the
 * authentication failure message in the status line and the body. For LDAP that message must
 * be the same for an unknown username and for a wrong password.
 */
class LdapLoginFailureMessageTest {

    private static final String NOT_A_SECRET = "test-fixture-not-a-secret-at-least-256-bits-long";

    private static InMemoryDirectoryServer server;
    private static EmbeddedServer embeddedServer;
    private static HttpClient httpClient;
    private static BlockingHttpClient client;

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapLoginFailureMessageTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        embeddedServer = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "micronaut.security.authentication", "bearer",
                "micronaut.security.token.jwt.signatures.secret.generator.secret", NOT_A_SECRET,
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ), "test");
        httpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, embeddedServer.getURL());
        client = httpClient.toBlocking();
    }

    @AfterAll
    static void cleanup() {
        if (httpClient != null) {
            httpClient.close();
        }
        if (embeddedServer != null) {
            embeddedServer.close();
        }
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void unknownUsernameAndWrongPasswordProduceTheSameLoginFailure() {
        HttpClientResponseException unknownUser = login("nobody-in-this-directory", "password");
        HttpClientResponseException wrongPassword = login("euclid", "wrong-password");

        assertEquals(HttpStatus.UNAUTHORIZED, unknownUser.getStatus());
        assertEquals(HttpStatus.UNAUTHORIZED, wrongPassword.getStatus());
        String unknownUserBody = unknownUser.getResponse().getBody(String.class).orElse("");
        String wrongPasswordBody = wrongPassword.getResponse().getBody(String.class).orElse("");
        assertFalse(unknownUserBody.contains("User Not Found"), unknownUserBody);
        assertEquals(wrongPasswordBody, unknownUserBody);
        assertEquals(wrongPassword.getResponse().reason(), unknownUser.getResponse().reason());
        assertEquals(wrongPassword.getResponse().getHeaders().getAll(HttpHeaders.WWW_AUTHENTICATE),
                unknownUser.getResponse().getHeaders().getAll(HttpHeaders.WWW_AUTHENTICATE));
    }

    @Test
    void validCredentialsReceiveAToken() {
        HttpResponse<String> response = client.exchange(HttpRequest.POST("/login", new UsernamePasswordCredentials("euclid", "password")), String.class);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertTrue(response.getBody().orElse("").contains("access_token"));
    }

    private static HttpClientResponseException login(String username, String password) {
        HttpRequest<?> request = HttpRequest.POST("/login", new UsernamePasswordCredentials(username, password));
        return assertThrows(HttpClientResponseException.class, () -> client.exchange(request, String.class));
    }
}
