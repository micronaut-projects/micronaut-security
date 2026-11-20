package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.Authenticator;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import jakarta.inject.Named;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A subclass of {@link LdapAuthenticationProviderFactory} which replaces it and overrides the factory method creates
 * the LDAP authentication provider, and the provider binds to the directory once per login as it did before 5.6.0.
 */
class LdapAuthenticationProviderFactorySubclassTest {

    private static final String USERNAME = "riemann";

    private static final AtomicInteger AUTHENTICATIONS = new AtomicInteger();
    private static final AtomicReference<ExecutorService> EXECUTOR_SERVICE = new AtomicReference<>();

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

    @BeforeEach
    void reset() {
        AUTHENTICATIONS.set(0);
        EXECUTOR_SERVICE.set(null);
    }

    @Test
    void theDefaultFactoryCreatesExactlyOneProvider() {
        try (ApplicationContext context = run("none")) {
            assertEquals(1, context.getBeansOfType(LdapAuthenticationProvider.class).size(),
                    "One LDAP configuration must produce exactly one provider");
            assertTrue(authenticate(context).isAuthenticated());
        }
    }

    @Test
    void aSubclassOverridingTheFactoryMethodCreatesExactlyOneProviderWhichBindsOncePerLogin() {
        try (ApplicationContext context = run("OverridingFactory")) {
            Collection<LdapAuthenticationProvider> providers = context.getBeansOfType(LdapAuthenticationProvider.class);

            assertEquals(1, providers.size(), "One LDAP configuration must produce exactly one provider");
            assertInstanceOf(CountingLdapAuthenticationProvider.class, providers.iterator().next(),
                    "The provider must come from the method the factory subclass overrides");
            assertNotNull(EXECUTOR_SERVICE.get(), "The override is passed the io executor, as before 5.6.0");

            assertTrue(authenticate(context).isAuthenticated());
            assertEquals(1, AUTHENTICATIONS.get(), "The directory must be bound once per login");
        }
    }

    /**
     * Micronaut lists the provider of a replacing factory which repeats the bean annotations twice, so the
     * {@link Authenticator} calls it twice per login. That predates 5.6.0; it must not get worse.
     */
    @Test
    void aSubclassRepeatingTheBeanAnnotationsIsNoWorseThanBefore() {
        try (ApplicationContext context = run("AnnotatedOverridingFactory")) {
            Collection<LdapAuthenticationProvider> providers = context.getBeansOfType(LdapAuthenticationProvider.class);

            assertTrue(providers.size() <= 2, "Before 5.6.0 the provider was listed twice, now " + providers.size());
            Map<LdapAuthenticationProvider, Boolean> distinct = new IdentityHashMap<>();
            providers.forEach(provider -> distinct.put(provider, true));
            assertEquals(1, distinct.size(), "Every entry must be the same provider instance");
            assertInstanceOf(CountingLdapAuthenticationProvider.class, providers.iterator().next());

            assertTrue(authenticate(context).isAuthenticated());
            assertTrue(AUTHENTICATIONS.get() <= 2, "Before 5.6.0 the directory was bound twice per login, now " + AUTHENTICATIONS.get());
        }
    }

    private static ApplicationContext run(String specName) {
        return ApplicationContext.run(LdapTestSupport.properties(server, Map.of("spec.name", specName)), "test");
    }

    @SuppressWarnings("unchecked")
    private static AuthenticationResponse authenticate(ApplicationContext context) {
        Publisher<AuthenticationResponse> publisher = context.getBean(Authenticator.class).authenticate(null, LdapTestSupport.request(USERNAME));
        CompletableFuture<AuthenticationResponse> result = new CompletableFuture<>();
        publisher.subscribe(new Subscriber<>() {
            @Override
            public void onSubscribe(Subscription subscription) {
                subscription.request(1);
            }

            @Override
            public void onNext(AuthenticationResponse response) {
                result.complete(response);
            }

            @Override
            public void onError(Throwable throwable) {
                result.completeExceptionally(throwable);
            }

            @Override
            public void onComplete() {
                result.completeExceptionally(new AssertionError("No authentication response"));
            }
        });
        try {
            return result.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    static class CountingLdapAuthenticationProvider extends LdapAuthenticationProvider<Object, String, String> {
        CountingLdapAuthenticationProvider(LdapConfiguration configuration,
                                           LdapSearchService ldapSearchService,
                                           ContextBuilder contextBuilder,
                                           ContextAuthenticationMapper contextAuthenticationMapper,
                                           LdapGroupProcessor ldapGroupProcessor) {
            super(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }

        @Override
        public AuthenticationResponse authenticate(Object requestContext, AuthenticationRequest<String, String> authenticationRequest) {
            AUTHENTICATIONS.incrementAndGet();
            return super.authenticate(requestContext, authenticationRequest);
        }
    }

    @Factory
    @Replaces(LdapAuthenticationProviderFactory.class)
    @Requires(property = "spec.name", value = "OverridingFactory")
    static class OverridingFactory extends LdapAuthenticationProviderFactory {
        @Override
        public LdapAuthenticationProvider ldapAuthenticationProvider(LdapConfiguration configuration,
                                                                     LdapSearchService ldapSearchService,
                                                                     ContextBuilder contextBuilder,
                                                                     ContextAuthenticationMapper contextAuthenticationMapper,
                                                                     LdapGroupProcessor ldapGroupProcessor,
                                                                     ExecutorService executorService) {
            EXECUTOR_SERVICE.set(executorService);
            return new CountingLdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }
    }

    @Factory
    @Replaces(LdapAuthenticationProviderFactory.class)
    @Requires(property = "spec.name", value = "AnnotatedOverridingFactory")
    static class AnnotatedOverridingFactory extends LdapAuthenticationProviderFactory {
        @Override
        @EachBean(LdapConfiguration.class)
        @Requires(condition = LdapEnabledCondition.class)
        public LdapAuthenticationProvider ldapAuthenticationProvider(@Parameter LdapConfiguration configuration,
                                                                     LdapSearchService ldapSearchService,
                                                                     ContextBuilder contextBuilder,
                                                                     ContextAuthenticationMapper contextAuthenticationMapper,
                                                                     LdapGroupProcessor ldapGroupProcessor,
                                                                     @Named(TaskExecutors.IO) ExecutorService executorService) {
            return new CountingLdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        }
    }
}
