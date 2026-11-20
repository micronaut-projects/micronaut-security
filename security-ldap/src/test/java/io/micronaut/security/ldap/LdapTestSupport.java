package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.security.authentication.AuthenticationRequest;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * The in-memory directory, the configuration pointing to it and the authentication requests shared by the LDAP tests.
 */
public final class LdapTestSupport {

    public static final String BASE_DN = "dc=example,dc=com";
    public static final String MANAGER_DN = "cn=admin," + BASE_DN;
    public static final String PASSWORD = "password";

    private LdapTestSupport() {
    }

    /**
     * Starts an in-memory directory with the entries of an LDIF file and a manager that binds with
     * {@link #MANAGER_DN} and {@link #PASSWORD}.
     *
     * @param ldifPath     The classpath location of the LDIF file
     * @param interceptors Interceptors to alter how the directory answers
     * @return A directory listening on a random port, which the caller has to shut down
     * @throws Exception If the directory cannot be started
     */
    public static InMemoryDirectoryServer startServer(String ldifPath, InMemoryOperationInterceptor... interceptors) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.addAdditionalBindCredentials(MANAGER_DN, PASSWORD);
        for (InMemoryOperationInterceptor interceptor : interceptors) {
            config.addInMemoryOperationInterceptor(interceptor);
        }
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapTestSupport.class.getClassLoader().getResourceAsStream(ldifPath)) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        return server;
    }

    /**
     * @param server The directory to authenticate against
     * @return The context and search configuration of the LDAP configuration named {@code default}, without the
     * {@code enabled} switch, in a map the caller can add to
     */
    public static Map<String, Object> connection(InMemoryDirectoryServer server) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort());
        properties.put("micronaut.security.ldap.default.context.managerDn", MANAGER_DN);
        properties.put("micronaut.security.ldap.default.context.managerPassword", PASSWORD);
        properties.put("micronaut.security.ldap.default.search.base", BASE_DN);
        return properties;
    }

    /**
     * @param server The directory to authenticate against
     * @return {@link #connection(InMemoryDirectoryServer)} with the configuration enabled
     */
    public static Map<String, Object> properties(InMemoryDirectoryServer server) {
        Map<String, Object> properties = connection(server);
        properties.put("micronaut.security.ldap.default.enabled", true);
        return properties;
    }

    /**
     * @param server     The directory to authenticate against
     * @param additional Properties to add to {@link #properties(InMemoryDirectoryServer)}
     * @return The merged properties
     */
    public static Map<String, Object> properties(InMemoryDirectoryServer server, Map<String, Object> additional) {
        Map<String, Object> properties = properties(server);
        properties.putAll(additional);
        return properties;
    }

    /**
     * @param username The username
     * @return A request to authenticate the user with {@link #PASSWORD}
     */
    public static AuthenticationRequest<String, String> request(String username) {
        return request(username, PASSWORD);
    }

    /**
     * @param username The username
     * @param password The password
     * @return A request to authenticate the user with the password
     */
    public static AuthenticationRequest<String, String> request(String username, String password) {
        return new AuthenticationRequest<>() {
            @Override
            public String getIdentity() {
                return username;
            }

            @Override
            public String getSecret() {
                return password;
            }
        };
    }
}
