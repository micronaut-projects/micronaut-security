package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A line break in a value that is logged could start a forged log entry (CWE-117). The username is supplied by an
 * unauthenticated client, and the diagnostic messages, DNs and group names are supplied by the directory. None of them may
 * reach the log with its line breaks.
 */
class LdapLogInjectionTest {

    private static final String SPEC_NAME = "LdapLogInjectionTest";
    private static final String FORGED_ENTRY = "12:00:00 INFO  Authentication succeeded for admin";
    private static final String LINE_BREAKS = "\r\n";
    private static final String USER = "riemann";
    private static final String USER_DN = "uid=riemann," + LdapTestSupport.BASE_DN;
    private static final String DECOY_DN = "cn=decoy," + LdapTestSupport.BASE_DN;

    private LogCapture log;

    @BeforeEach
    void captureLog() {
        log = LogCapture.start("io.micronaut.security.ldap", Level.TRACE);
    }

    @AfterEach
    void restoreLog() {
        log.close();
    }

    @Test
    void lineBreaksInTheUsernameAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");

        AuthenticationResponse response = authenticate(server, Map.of(), "nobody" + LINE_BREAKS + FORGED_ENTRY + " ");

        assertFalse(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInTheDiagnosticMessageOfTheDirectoryAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", rejectBind(USER_DN, ResultCode.INVALID_CREDENTIALS));

        AuthenticationResponse response = authenticate(server, Map.of(), USER);

        assertFalse(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInTheDiagnosticMessageOfARejectedManagerBindAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif",
                rejectBind(LdapTestSupport.MANAGER_DN, ResultCode.INVALID_CREDENTIALS));

        AuthenticationResponse response = authenticate(server, Map.of(), USER);

        assertFalse(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @ParameterizedTest(name = "result code {0} to the decoy bind is logged at {1} without line breaks")
    @CsvSource({
            // the expected failure of the decoy bind
            "49, DEBUG",
            // a result code other than invalid credentials makes the provider warn about the decoy, at a level enabled by default
            "53, WARN",
    })
    void lineBreaksInTheDiagnosticMessageOfTheDecoyBindAreNotLogged(int resultCode, String level) throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", rejectBind(DECOY_DN, ResultCode.valueOf(resultCode)));

        AuthenticationResponse response = authenticate(server, Map.of("micronaut.security.ldap.default.search.decoy-dn", DECOY_DN), "nobody");

        assertFalse(response.isAuthenticated());
        assertTrue(log.events().stream().anyMatch(event -> event.getLevel() == Level.toLevel(level) && event.getFormattedMessage().contains("Decoy bind")
                        && event.getFormattedMessage().contains(FORGED_ENTRY)),
                "the decoy log line is expected to carry the diagnostic message: " + log.messages());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInTheDnOfTheUserAreNotLogged() throws Exception {
        // the directory escapes the line breaks of a DN (RFC 4514), so they reach the provider only through a custom
        // search service: sanitizing the DN is defence in depth
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        String uid = "forged" + LINE_BREAKS + FORGED_ENTRY;
        DN dn = new DN(new RDN("uid", uid), new DN(LdapTestSupport.BASE_DN));
        server.add(new Entry(dn,
                new Attribute("objectClass", "inetOrgPerson"),
                new Attribute("uid", uid),
                new Attribute("cn", "forged"),
                new Attribute("sn", "forged"),
                new Attribute("userPassword", LdapTestSupport.PASSWORD)));
        server.add(new Entry("cn=staff," + LdapTestSupport.BASE_DN,
                new Attribute("objectClass", "groupOfUniqueNames"),
                new Attribute("cn", "staff"),
                new Attribute("uniqueMember", dn.toString())));

        // groups are enabled, and the user is a member of one, so that the group processor logs the DN too
        AuthenticationResponse response = authenticate(server, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN
        ), uid);

        assertTrue(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInAGroupNameAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        server.add(new Entry("cn=forged," + LdapTestSupport.BASE_DN,
                new Attribute("objectClass", "groupOfUniqueNames"),
                new Attribute("cn", "forged", "staff" + LINE_BREAKS + FORGED_ENTRY),
                new Attribute("uniqueMember", USER_DN)));

        AuthenticationResponse response = authenticate(server, Map.of(
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN
        ), USER);

        assertTrue(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    /**
     * @param bindDn     The DN whose bind the directory rejects
     * @param resultCode The result code of the rejection
     * @return An interceptor that rejects the bind with a diagnostic message carrying a forged log entry
     */
    private static InMemoryOperationInterceptor rejectBind(String bindDn, ResultCode resultCode) {
        return new InMemoryOperationInterceptor() {
            @Override
            public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                if (bindDn.equals(request.getRequest().getBindDN())) {
                    throw new LDAPException(resultCode, "denied" + LINE_BREAKS + FORGED_ENTRY);
                }
            }
        };
    }

    private static AuthenticationResponse authenticate(InMemoryDirectoryServer server, Map<String, Object> properties, String username) {
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, properties), "test")) {
            return LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request(username));
        } finally {
            server.shutDown(true);
        }
    }

    private void assertForgedEntryIsLoggedWithoutLineBreaks() {
        List<String> messages = log.messages();
        assertTrue(messages.stream().anyMatch(message -> message.contains(FORGED_ENTRY)), "the value is expected in the log: " + messages);
        for (String message : messages) {
            // the characters LoggingUtils#sanitize replaces; \p{Cntrl} would miss C1 controls such as NEL (U+0085)
            assertFalse(message.chars().anyMatch(c -> Character.isISOControl(c) || c == '\u2028' || c == '\u2029'), "control character logged: " + message);
        }
    }

    /**
     * Stands in for a custom search service that returns the DN of an entry with its line breaks unescaped.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultLdapSearchService.class)
    @Singleton
    static class UnescapedDnLdapSearchService extends DefaultLdapSearchService {

        @Override
        protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> results) throws NamingException {
            List<LdapSearchResult> searchResults = new ArrayList<>();
            while (results.hasMore()) {
                SearchResult result = results.next();
                searchResults.add(new LdapSearchResult(result.getAttributes(), result.getNameInNamespace().replace("\\0d\\0a", LINE_BREAKS)));
            }
            return searchResults;
        }
    }
}
