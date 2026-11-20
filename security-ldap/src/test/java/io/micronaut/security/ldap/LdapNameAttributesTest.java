package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.AttributesConvertibleValues;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.ContextSettings;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.context.SearchSettings;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.io.InputStream;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * When a custom LDAP search service returns a result without attributes, the provider must
 * fetch them using an LDAP name so that DNs containing a slash can be resolved.
 */
@NullMarked
class LdapNameAttributesTest {

    private static final String SPEC_NAME = "LdapNameAttributesTest";
    private static final String BASE_DN = "dc=example,dc=com";
    private static final String MANAGER_DN = "cn=admin," + BASE_DN;
    private static final String MANAGER_PASSWORD = "password";
    // the password of every user in the LDIF fixtures
    private static final String USER_PASSWORD = "password";

    private @Nullable InMemoryDirectoryServer server;

    @AfterEach
    void stopDirectory() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @ParameterizedTest(name = "attributes are fetched for {2}")
    @MethodSource("users")
    @SuppressWarnings("unchecked")
    void attributesAreFetchedWithTheUserContextWhenTheSearchResultHasNone(String ldif, String username, String dn, String cn) throws Exception {
        try (ApplicationContext context = startContext(ldif)) {
            LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);
            NullAttributesLdapSearchService searchService = context.getBean(NullAttributesLdapSearchService.class);

            AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials(username, USER_PASSWORD));

            assertTrue(response.isAuthenticated());
            assertEquals(username, response.getAuthentication().orElseThrow().getName());
            LdapSearchResult result = searchService.lastResult;
            assertNotNull(result);
            assertEquals(dn, result.getDn());
            ConvertibleValues<Object> attributes = result.getAttributes();
            assertNotNull(attributes);
            assertEquals(username, attributes.get("uid", String.class).orElseThrow());
            assertEquals(cn, attributes.get("cn", String.class).orElseThrow());
        }
    }

    @ParameterizedTest(name = "wrong password is rejected for {2}")
    @MethodSource("users")
    @SuppressWarnings("unchecked")
    void wrongPasswordIsRejectedWithoutFetchingAttributes(String ldif, String username, String dn) throws Exception {
        try (ApplicationContext context = startContext(ldif)) {
            LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);
            NullAttributesLdapSearchService searchService = context.getBean(NullAttributesLdapSearchService.class);

            AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials(username, "wrong-password"));

            assertFalse(response.isAuthenticated());
            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH,
                assertInstanceOf(AuthenticationFailed.class, response).getReason());
            LdapSearchResult result = searchService.lastResult;
            assertNotNull(result);
            assertEquals(dn, result.getDn());
            assertNull(result.getAttributes());
        }
    }

    /**
     * Pins the contract that a DN which cannot be parsed ends as an UNKNOWN failure and no exception
     * escapes the provider. It does not prove where the DN is rejected: without the {@code LdapName}
     * parse the directory server rejects the same DN, with the same outcome. The parameterized tests
     * above are the ones that guard the {@code LdapName} parse.
     */
    @Test
    void malformedDnIsAnUnknownFailureRatherThanAnException() throws Exception {
        try (ApplicationContext context = startContext("basic.ldif")) {
            ContextBuilder contextBuilder = context.getBean(ContextBuilder.class);
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            // binds every user as the manager, so that the malformed DN reaches the attribute lookup
            ContextBuilder bindsAsManager = new ContextBuilder() {
                @Override
                public DirContext build(ContextSettings contextSettings) throws NamingException {
                    return contextBuilder.build(configuration.getManagerSettings());
                }

                @Override
                public DirContext build(String factory, String server, String user, String password, boolean pooled) throws NamingException {
                    return contextBuilder.build(factory, server, user, password, pooled);
                }

                @Override
                public void close(DirContext dirContext) {
                    contextBuilder.close(dirContext);
                }
            };
            LdapSearchService malformedDn = new DefaultLdapSearchService() {
                @Override
                public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) {
                    return Optional.of(new NullAttributesLdapSearchResult("not-a-distinguished-name"));
                }
            };
            LdapAuthenticationProvider<Object, String, String> provider = new LdapAuthenticationProvider<>(
                configuration,
                malformedDn,
                bindsAsManager,
                context.getBean(ContextAuthenticationMapper.class),
                context.getBean(LdapGroupProcessor.class),
                context.getBean(ExecutorService.class, Qualifiers.byName(TaskExecutors.IO)));

            AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials("riemann", USER_PASSWORD));

            assertFalse(response.isAuthenticated());
            assertEquals(AuthenticationFailureReason.UNKNOWN,
                assertInstanceOf(AuthenticationFailed.class, response).getReason());
        }
    }

    private static Stream<Arguments> users() {
        return Stream.of(
            Arguments.of("special-characters-dn.ldif", "johndoe", "cn=John/Doe,dc=example,dc=com", "John/Doe"),
            Arguments.of("special-characters-dn.ldif", "janedoe", "cn=Jane \\\"JD\\\" Doe,dc=example,dc=com", "Jane \"JD\" Doe"),
            Arguments.of("basic.ldif", "riemann", "uid=riemann,dc=example,dc=com", "riemann")
        );
    }

    private ApplicationContext startContext(String ldifPath) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.addAdditionalBindCredentials(MANAGER_DN, MANAGER_PASSWORD);
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream(ldifPath));
             LDIFReader reader = new LDIFReader(ldif)) {
            server.importFromLDIF(true, reader);
        }
        server.startListening();
        return ApplicationContext.run(Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.ldap.default.enabled", true,
            "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
            "micronaut.security.ldap.default.context.managerDn", MANAGER_DN,
            "micronaut.security.ldap.default.context.managerPassword", MANAGER_PASSWORD,
            "micronaut.security.ldap.default.search.base", BASE_DN
        ), "test");
    }

    /**
     * Stands in for a custom search service that leaves attributes to be fetched after the user binds.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultLdapSearchService.class)
    @Singleton
    static class NullAttributesLdapSearchService extends DefaultLdapSearchService {

        private @Nullable LdapSearchResult lastResult;

        @Override
        public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
            lastResult = super.searchFirst(managerContext, settings)
                .map(result -> new NullAttributesLdapSearchResult(result.getDn()))
                .orElse(null);
            return Optional.ofNullable(lastResult);
        }
    }

    /**
     * Returns null attributes until they are fetched using the bound user context.
     */
    static class NullAttributesLdapSearchResult extends LdapSearchResult {

        private @Nullable ConvertibleValues<Object> fetched;

        NullAttributesLdapSearchResult(String dn) {
            super(null, dn);
        }

        @Override
        public @Nullable ConvertibleValues<Object> getAttributes() {
            return fetched;
        }

        @Override
        public void setAttributes(@Nullable Attributes attributes) {
            if (attributes != null) {
                fetched = new AttributesConvertibleValues(attributes);
            }
        }
    }
}
