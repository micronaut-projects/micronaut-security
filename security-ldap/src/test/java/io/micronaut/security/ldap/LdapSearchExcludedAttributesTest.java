package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@NullMarked
class LdapSearchExcludedAttributesTest {

    private static InMemoryDirectoryServer server;
    private final Logger logger = (Logger) LoggerFactory.getLogger(LdapConfiguration.class);
    private ListAppender<ILoggingEvent> appender;
    private @Nullable Level previousLevel;

    @BeforeEach
    void captureWarnings() {
        previousLevel = logger.getLevel();
        logger.setLevel(Level.WARN);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void stopCapturingWarnings() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(previousLevel);
    }

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapSearchExcludedAttributesTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
    }

    @AfterAll
    static void cleanup() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void excludedAttributesDefaultToUserPasswordAndUnicodePwd() {
        try (ApplicationContext context = ApplicationContext.run(properties(), "test")) {
            LdapConfiguration.SearchConfiguration search = context.getBean(LdapConfiguration.class).getSearch();

            assertEquals(List.of("userPassword", "unicodePwd"), search.getExcludedAttributes());
            assertNull(search.getAttributes());
        }
    }

    @Test
    void userPasswordIsStrippedFromTheSearchResultByDefault() {
        try (ApplicationContext context = ApplicationContext.run(properties(), "test")) {
            Set<String> names = lowerCaseAttributeNames(authenticate(context));

            assertTrue(names.contains("uid"));
            assertTrue(names.contains("cn"));
            assertTrue(names.contains("sn"));
            assertFalse(names.contains("userpassword"));
            assertTrue(appender.list.isEmpty());
        }
    }

    @Test
    void userPasswordIsReturnedWhenExcludedAttributesIsCleared() {
        Map<String, Object> properties = properties();
        properties.put("micronaut.security.ldap.default.search.excluded-attributes", List.of());
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            assertTrue(context.getBean(LdapConfiguration.class).getSearch().getExcludedAttributes().isEmpty());

            Set<String> names = lowerCaseAttributeNames(authenticate(context));

            assertTrue(names.contains("uid"));
            assertTrue(names.contains("userpassword"));
        }
    }

    @Test
    void excludedAttributesCanBeExtendedWithAdditionalAttributes() {
        Map<String, Object> properties = properties();
        properties.put("micronaut.security.ldap.default.search.excluded-attributes", List.of("userPassword", "SN"));
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            Set<String> names = lowerCaseAttributeNames(authenticate(context));

            assertTrue(names.contains("uid"));
            assertTrue(names.contains("cn"));
            assertFalse(names.contains("sn"));
            assertFalse(names.contains("userpassword"));
        }
    }

    @Test
    void anExplicitAttributesListRestrictsTheReturnedAttributes() {
        Map<String, Object> properties = properties();
        properties.put("micronaut.security.ldap.default.search.attributes", List.of("cn", "sn"));
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            assertEquals(Set.of("cn", "sn"), lowerCaseAttributeNames(authenticate(context)));
        }
    }

    @Test
    void anExcludedAttributeIsStrippedEvenWhenRequestedExplicitly() {
        Map<String, Object> properties = properties();
        properties.put("micronaut.security.ldap.default.search.attributes", List.of("cn", "userPassword"));
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            assertEquals(Set.of("cn"), lowerCaseAttributeNames(authenticate(context)));
            authenticate(context);

            assertEquals(1, appender.list.size(), "the conflict must be logged once, not on every authentication");
            assertEquals(Level.WARN, appender.list.getFirst().getLevel());
            assertTrue(appender.list.getFirst().getFormattedMessage().contains("requests search attribute [userPassword]"));
            assertTrue(appender.list.getFirst().getFormattedMessage().contains("search.excluded-attributes"));
        }
    }

    @Test
    void anExcludedGroupFilterAttributeLogsAStartupWarning() {
        Map<String, Object> properties = properties();
        properties.put("micronaut.security.ldap.default.search.excluded-attributes", List.of("SN"));
        properties.put("micronaut.security.ldap.default.groups.filter-attribute", "sn");
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            context.getBean(LdapConfiguration.class);

            assertEquals(1, appender.list.size());
            assertEquals(Level.WARN, appender.list.getFirst().getLevel());
            assertTrue(appender.list.getFirst().getFormattedMessage().contains("groups.filter-attribute [SN]"));
            assertTrue(appender.list.getFirst().getFormattedMessage().contains("search.excluded-attributes"));
        }
    }

    @Test
    void excludedAttributesAreDefensivelyCopied() {
        LdapConfiguration.SearchConfiguration search = new LdapConfiguration.SearchConfiguration();
        List<String> excluded = new ArrayList<>(List.of("userPassword"));

        search.setExcludedAttributes(excluded);
        excluded.clear();

        assertEquals(List.of("userPassword"), search.getExcludedAttributes());
        assertThrows(UnsupportedOperationException.class, () -> search.getExcludedAttributes().clear());
        search.setExcludedAttributes(null);
        assertTrue(search.getExcludedAttributes().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void existingCreateResultsOverrideIsCalledWithAndWithoutExclusions(boolean clearExclusions) throws NamingException {
        Map<String, Object> properties = properties();
        if (clearExclusions) {
            properties.put("micronaut.security.ldap.default.search.excluded-attributes", List.of());
        }
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            ContextBuilder contextBuilder = context.getBean(ContextBuilder.class);
            DirContext managerContext = contextBuilder.build(configuration.getManagerSettings());
            class CustomSearchService extends DefaultLdapSearchService {
                private boolean called;

                @Override
                protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> results) throws NamingException {
                    called = true;
                    List<LdapSearchResult> converted = super.createResults(results);
                    assertEquals(1, converted.size());
                    assertEquals(clearExclusions, converted.getFirst().getAttributes().names().stream()
                        .anyMatch(name -> name.equalsIgnoreCase("userPassword")));
                    // An existing subclass can still filter the returned entries.
                    return List.of();
                }
            }
            CustomSearchService service = new CustomSearchService();
            try {
                assertTrue(service.search(managerContext, configuration.getSearch().getSettings(new Object[]{"riemann"})).isEmpty());
                assertTrue(service.called);
            } finally {
                contextBuilder.close(managerContext);
            }
        }
    }

    private static Map<String, Object> properties() {
        return new HashMap<>(Map.of(
            "spec.name", "LdapSearchExcludedAttributesTest",
            "micronaut.security.ldap.default.enabled", true,
            "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
            "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
            "micronaut.security.ldap.default.context.managerPassword", "password",
            "micronaut.security.ldap.default.search.base", "dc=example,dc=com",
            "micronaut.security.ldap.default.groups.enabled", true,
            "micronaut.security.ldap.default.groups.base", "dc=example,dc=com"
        ));
    }

    @SuppressWarnings("unchecked")
    private static Authentication authenticate(ApplicationContext context) {
        LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);
        AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials("riemann", "password"));

        assertTrue(response.isAuthenticated());
        Authentication authentication = response.getAuthentication().orElseThrow();
        assertEquals("riemann", authentication.getName());
        assertEquals(Set.of("Mathematicians"), Set.copyOf(authentication.getRoles()));
        return authentication;
    }

    private static Set<String> lowerCaseAttributeNames(Authentication authentication) {
        return authentication.getAttributes().keySet().stream()
            .map(name -> name.toLowerCase(Locale.ROOT))
            .collect(Collectors.toSet());
    }
}
