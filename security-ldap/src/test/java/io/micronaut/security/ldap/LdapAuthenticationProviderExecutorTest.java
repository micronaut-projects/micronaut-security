package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link LdapAuthenticationProvider} runs on the executor named by
 * {@link LdapAuthenticationProvider#getExecutorName()}. The executor service the deprecated constructor and the
 * deprecated factory method take is never used.
 */
class LdapAuthenticationProviderExecutorTest {

    private static final String USERNAME = "riemann";

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;

    @BeforeAll
    static void setup() throws Exception {
        server = LdapTestSupport.startServer("basic.ldif");
        context = ApplicationContext.run(LdapTestSupport.properties(server), "test");
    }

    @AfterAll
    static void cleanup() {
        if (context != null) {
            context.close();
        }
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void onlyTheFactoryMethodWithoutAnExecutorServiceCreatesAProviderWhichRunsOnTheBlockingExecutor() {
        assertEquals(1, context.getBeansOfType(LdapAuthenticationProvider.class).size(),
                "One LDAP configuration must produce one provider: the deprecated factory method must not be a bean");
        assertEquals(TaskExecutors.BLOCKING, context.getBean(LdapAuthenticationProvider.class).getExecutorName());
    }

    @Test
    @SuppressWarnings("unchecked")
    void theProviderCreatedByTheFactoryAuthenticates() {
        assertAuthenticates(context.getBean(LdapAuthenticationProvider.class));
    }

    @Test
    @SuppressWarnings("removal")
    void theDeprecatedConstructorIgnoresTheExecutorService() {
        LdapAuthenticationProvider<Object, String, String> provider = new LdapAuthenticationProvider<>(
                context.getBean(LdapConfiguration.class),
                context.getBean(LdapSearchService.class),
                context.getBean(ContextBuilder.class),
                context.getBean(ContextAuthenticationMapper.class),
                context.getBean(LdapGroupProcessor.class),
                unusableExecutorService());

        assertEquals(TaskExecutors.BLOCKING, provider.getExecutorName());
        assertAuthenticates(provider);
    }

    @Test
    @SuppressWarnings({"removal", "unchecked"})
    void theDeprecatedFactoryMethodIgnoresTheExecutorService() {
        LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProviderFactory.class).ldapAuthenticationProvider(
                context.getBean(LdapConfiguration.class),
                context.getBean(LdapSearchService.class),
                context.getBean(ContextBuilder.class),
                context.getBean(ContextAuthenticationMapper.class),
                context.getBean(LdapGroupProcessor.class),
                unusableExecutorService());

        assertEquals(TaskExecutors.BLOCKING, provider.getExecutorName());
        assertAuthenticates(provider);
    }

    private static void assertAuthenticates(LdapAuthenticationProvider<Object, String, String> provider) {
        AuthenticationResponse response = provider.authenticate(null, LdapTestSupport.request(USERNAME));

        assertTrue(response.isAuthenticated());
        assertEquals(USERNAME, response.getAuthentication().orElseThrow().getName());
    }

    /**
     * @return An executor service which fails the test as soon as anything is invoked on it
     */
    private static ExecutorService unusableExecutorService() {
        return (ExecutorService) Proxy.newProxyInstance(
                LdapAuthenticationProviderExecutorTest.class.getClassLoader(),
                new Class<?>[] {ExecutorService.class},
                (proxy, method, args) -> {
                    throw new AssertionError("The executor service must be ignored but " + method.getName() + " was invoked");
                });
    }
}
