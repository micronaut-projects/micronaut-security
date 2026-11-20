package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * A subclass of {@link LdapAuthenticationProviderFactory} which replaces it and overrides either factory method, without
 * repeating the bean annotations, creates the LDAP authentication provider.
 */
class LdapAuthenticationProviderFactorySubclassTest {

    private static InMemoryDirectoryServer server;

    @BeforeAll
    static void setup() throws Exception {
        server = LdapTestSupport.startServer("basic.ldif");
    }

    @AfterAll
    static void cleanup() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void aSubclassOverridingTheDeprecatedFactoryMethodCreatesTheProvider() {
        assertOnlyCustomProviders("DeprecatedMethodFactory");
    }

    @Test
    void aSubclassOverridingTheFactoryMethodWithoutAnExecutorServiceCreatesTheProvider() {
        assertOnlyCustomProviders("MethodFactory");
    }

    @SuppressWarnings("rawtypes")
    private static void assertOnlyCustomProviders(String specName) {
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of("spec.name", specName)), "test")) {
            Collection<LdapAuthenticationProvider> providers = context.getBeansOfType(LdapAuthenticationProvider.class);

            assertFalse(providers.isEmpty());
            providers.forEach(provider -> assertInstanceOf(CustomLdapAuthenticationProvider.class, provider,
                    "The provider must come from the method the factory subclass overrides"));
        }
    }

    @SuppressWarnings("rawtypes")
    static class CustomLdapAuthenticationProvider extends LdapAuthenticationProvider {
        CustomLdapAuthenticationProvider(LdapConfiguration configuration,
                                         LdapSearchService ldapSearchService,
                                         ContextBuilder contextBuilder,
                                         ContextAuthenticationMapper contextAuthenticationMapper,
                                         LdapGroupProcessor ldapGroupProcessor) {
            super(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }
    }

    @Factory
    @Replaces(LdapAuthenticationProviderFactory.class)
    @Requires(property = "spec.name", value = "DeprecatedMethodFactory")
    static class DeprecatedMethodFactory extends LdapAuthenticationProviderFactory {
        @Override
        @SuppressWarnings("removal")
        public LdapAuthenticationProvider ldapAuthenticationProvider(LdapConfiguration configuration,
                                                                     LdapSearchService ldapSearchService,
                                                                     ContextBuilder contextBuilder,
                                                                     ContextAuthenticationMapper contextAuthenticationMapper,
                                                                     LdapGroupProcessor ldapGroupProcessor,
                                                                     ExecutorService executorService) {
            return new CustomLdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }
    }

    @Factory
    @Replaces(LdapAuthenticationProviderFactory.class)
    @Requires(property = "spec.name", value = "MethodFactory")
    static class MethodFactory extends LdapAuthenticationProviderFactory {
        @Override
        public LdapAuthenticationProvider ldapAuthenticationProvider(LdapConfiguration configuration,
                                                                     LdapSearchService ldapSearchService,
                                                                     ContextBuilder contextBuilder,
                                                                     ContextAuthenticationMapper contextAuthenticationMapper,
                                                                     LdapGroupProcessor ldapGroupProcessor) {
            return new CustomLdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }
    }
}
