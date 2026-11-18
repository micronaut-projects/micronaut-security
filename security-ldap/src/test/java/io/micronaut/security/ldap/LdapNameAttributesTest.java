package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.context.AttributesConvertibleValues;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.SearchSettings;
import jakarta.inject.Singleton;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * When a custom {@link io.micronaut.security.ldap.context.LdapSearchService} returns a result without attributes,
 * {@link LdapAuthenticationProvider} fetches them with the user context. The DN must be parsed as an LDAP name, not
 * as a JNDI composite name, otherwise DNs containing characters such as '/' or '"' cannot be resolved.
 */
class LdapNameAttributesTest {

    private static final String SPEC_NAME = "LdapNameAttributesTest";
    private static final String MANAGER_DN = "cn=admin,dc=example,dc=com";

    @ParameterizedTest(name = "attributes are fetched with the user context for DN {2}")
    @CsvSource(quoteCharacter = '\'', value = {
            "slash.ldif, johndoe,   'cn=John/Doe,dc=example,dc=com',   John/Doe",
            "quote.ldif, johnquote, 'cn=John\\\"Doe,dc=example,dc=com', John\"Doe",
            "basic.ldif, riemann,   'uid=riemann,dc=example,dc=com',   riemann",
    })
    @SuppressWarnings("unchecked")
    void attributesAreFetchedWithTheUserContextWhenTheSearchResultHasNone(String ldif, String username, String dn, String cn) throws Exception {
        InMemoryDirectoryServer server = startServer(ldif);
        try (ApplicationContext context = ApplicationContext.run(Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", MANAGER_DN,
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ), "test")) {
            LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);

            AuthenticationResponse response = provider.authenticate(null, request(username));

            assertTrue(response.isAuthenticated());
            assertEquals(username, response.getAuthentication().orElseThrow().getName());
            LdapSearchResult result = context.getBean(NullAttributesLdapSearchService.class).lastResult;
            assertEquals(dn, result.getDn());
            assertNotNull(result.getAttributes(), "the provider must fetch the attributes the search did not return");
            assertEquals(username, result.getAttributes().get("uid", String.class).orElseThrow());
            assertEquals(cn, result.getAttributes().get("cn", String.class).orElseThrow());
        } finally {
            server.shutDown(true);
        }
    }

    private static InMemoryDirectoryServer startServer(String ldifPath) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials(MANAGER_DN, "password");
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapNameAttributesTest.class.getClassLoader().getResourceAsStream(ldifPath)) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        return server;
    }

    private static AuthenticationRequest<String, String> request(String username) {
        return new AuthenticationRequest<>() {
            @Override
            public String getIdentity() {
                return username;
            }

            @Override
            public String getSecret() {
                return "password";
            }
        };
    }

    /**
     * A search service, standing in for a custom implementation, that returns results without attributes.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultLdapSearchService.class)
    @Singleton
    static class NullAttributesLdapSearchService extends DefaultLdapSearchService {

        volatile LdapSearchResult lastResult;

        @Override
        public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
            Optional<LdapSearchResult> result = super.searchFirst(managerContext, settings);
            result.ifPresent(found -> lastResult = new NullAttributesLdapSearchResult(found.getDn()));
            return result.map(found -> lastResult);
        }
    }

    /**
     * An {@link LdapSearchResult} whose attributes are null until they are populated from a non-null {@link Attributes}.
     */
    static class NullAttributesLdapSearchResult extends LdapSearchResult {

        private ConvertibleValues<Object> fetched;

        NullAttributesLdapSearchResult(String dn) {
            super(null, dn);
        }

        @Override
        public ConvertibleValues<Object> getAttributes() {
            return fetched;
        }

        @Override
        public void setAttributes(Attributes attributes) {
            if (attributes != null) {
                fetched = new AttributesConvertibleValues(attributes);
            }
        }
    }
}
