package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.security.authentication.AuthenticationFailureReason;
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

    @ParameterizedTest(name = "attributes are fetched with the user context for DN {2}")
    @CsvSource(quoteCharacter = '\'', value = {
            "slash.ldif, johndoe,   'cn=John/Doe,dc=example,dc=com',   John/Doe",
            "quote.ldif, johnquote, 'cn=John\\\"Doe,dc=example,dc=com', John\"Doe",
            "basic.ldif, riemann,   'uid=riemann,dc=example,dc=com',   riemann",
    })
    void attributesAreFetchedWithTheUserContextWhenTheSearchResultHasNone(String ldif, String username, String dn, String cn) throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer(ldif);
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of("spec.name", SPEC_NAME)), "test")) {
            AuthenticationResponse response = LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request(username));

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

    @ParameterizedTest(name = "result code {0} to the attribute fetch yields {1}")
    @CsvSource({
            "48, CREDENTIALS_DO_NOT_MATCH",
            "49, CREDENTIALS_DO_NOT_MATCH",
            "50, CREDENTIALS_DO_NOT_MATCH",
            "53, CREDENTIALS_DO_NOT_MATCH",
            "52, UNKNOWN",
    })
    void aFailingAttributeFetchYieldsUnknownOnlyForAnOutageAndIsLoggedAtWarn(int resultCode, AuthenticationFailureReason expected) throws Exception {
        String dn = "uid=riemann," + LdapTestSupport.BASE_DN;
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", new InMemoryOperationInterceptor() {
            @Override
            public void processSearchRequest(InMemoryInterceptedSearchRequest request) throws LDAPException {
                // the attribute fetch reads the entry itself; the user search is a subtree search of the base
                if (request.getRequest().getScope() == SearchScope.BASE && dn.equalsIgnoreCase(request.getRequest().getBaseDN())) {
                    throw new LDAPException(ResultCode.valueOf(resultCode), "simulated " + ResultCode.valueOf(resultCode).getName());
                }
            }
        });
        try (LogCapture log = LogCapture.start(LdapAuthenticationProvider.class.getName(), Level.DEBUG);
             ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of("spec.name", SPEC_NAME)), "test")) {
            AuthenticationResponse response = LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request("riemann"));

            assertEquals(expected, LdapTestSupport.failureReason(response));
            // only a client with the correct password reaches the attribute fetch, whose failure usually means a misconfiguration
            assertTrue(log.events().stream().anyMatch(event -> event.getLevel() == Level.WARN
                            && event.getFormattedMessage().startsWith("LDAP attribute fetch failed for user [riemann] after a successful bind; returning " + expected + ".")),
                    "the log is expected to blame the attribute fetch at WARN: " + log.messages());
        } finally {
            server.shutDown(true);
        }
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
