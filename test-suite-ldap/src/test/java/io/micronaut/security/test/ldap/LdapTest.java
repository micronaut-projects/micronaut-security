package io.micronaut.security.test.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LdapTest implements TestPropertyProvider {

    private static final String LDIF_CONTENT = """
        dn: dc=example,dc=com
        objectclass: domain
        objectclass: top

        dn: uid=riemann,dc=example,dc=com
        objectclass: inetOrgPerson
        uid: riemann
        sn: riemann
        cn: riemann
        userpassword: password
        """;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Override
    public Map<String, String> getProperties() {
        InMemoryDirectoryServer directoryServer;
        try {
            directoryServer = createDirectoryServer();
            directoryServer.startListening();
        } catch (LDAPException e) {
            throw new RuntimeException("Failed to create in memory directory server", e);
        }
        Map<String, String> properties = new HashMap<>();
        properties.put("micronaut.security.ldap.default.context.server", "ldap://localhost:" + directoryServer.getListenPort());
        return properties;
    }

    private InMemoryDirectoryServer createDirectoryServer() throws LDAPException {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");

        InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
        InputStream inputStream = new ByteArrayInputStream(LDIF_CONTENT.getBytes());
        directoryServer.importFromLDIF(true, new LDIFReader(inputStream));
        return directoryServer;
    }

    @Test
    void foo() {
        HttpRequest request = HttpRequest.POST("/login", new UsernamePasswordCredentials("riemann", "password"));
        HttpResponse<Boolean> response = httpClient.toBlocking().exchange(request, Boolean.class);
        Optional<Boolean> isAuthenticated = response.getBody();
        assertTrue(isAuthenticated.isPresent());
        assertTrue(isAuthenticated.get());
    }
}
