package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.context.ContextSettings;
import io.micronaut.security.ldap.context.DefaultContextBuilder;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.SearchSettings;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.naming.AuthenticationNotSupportedException;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;
import javax.naming.OperationNotSupportedException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.DirContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static io.micronaut.security.ldap.LdapTestSupport.failureReason;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies how {@link LdapAuthenticationProvider} maps exceptions to failure reasons depending on where they are
 * thrown. A failure of the manager bind or of the user search, which happens before the user is known, and an outage
 * during the bind of the user yield UNKNOWN. Any other failure of the bind of the user, and any failure after it
 * succeeded, outages included, yields CREDENTIALS_DO_NOT_MATCH, so that the reason reveals neither the user nor the
 * password.
 */
class LdapBindFailureReasonTest {

    private static final String SPEC_NAME = "LdapBindFailureReasonTest";

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;

    @BeforeAll
    static void setup() throws Exception {
        server = LdapTestSupport.startServer("basic.ldif");
        context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN
        )), "test");
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

    @AfterEach
    void everyContextOpenedIsClosedAndReset() {
        FailingContextBuilder contextBuilder = context.getBean(FailingContextBuilder.class);
        int opened = contextBuilder.opened.getAndSet(0);
        int closed = contextBuilder.closed.getAndSet(0);
        contextBuilder.managerException = null;
        contextBuilder.userException = null;
        FailingLdapSearchService searchService = context.getBean(FailingLdapSearchService.class);
        searchService.exception = null;
        searchService.groupException = null;
        assertEquals(opened, closed, "every context the provider opens has to be closed");
    }

    static Stream<Arguments> userBindFailures() {
        return Stream.of(
                Arguments.of(new AuthenticationNotSupportedException("not supported"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new OperationNotSupportedException("[LDAP: error code 53]"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new javax.naming.AuthenticationException("invalid credentials"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new NoPermissionException("[LDAP: error code 50]"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new NamingException("[LDAP: error code 80]"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new CommunicationException("connection reset"), AuthenticationFailureReason.UNKNOWN),
                Arguments.of(new ServiceUnavailableException("unavailable"), AuthenticationFailureReason.UNKNOWN)
        );
    }

    static Stream<NamingException> managerBindFailures() {
        return Stream.of(
                new javax.naming.AuthenticationException("invalid credentials"),
                new AuthenticationNotSupportedException("not supported"),
                new OperationNotSupportedException("[LDAP: error code 53]"),
                new CommunicationException("connection refused")
        );
    }

    static Stream<NamingException> searchFailures() {
        return Stream.of(
                new javax.naming.AuthenticationException("referral bind rejected"),
                new AuthenticationNotSupportedException("not supported"),
                new OperationNotSupportedException("[LDAP: error code 53]")
        );
    }

    @ParameterizedTest(name = "{0} during the user bind yields {1}")
    @MethodSource("userBindFailures")
    void exceptionDuringTheUserBindDecidesTheFailureReason(NamingException exception, AuthenticationFailureReason expected) {
        context.getBean(FailingContextBuilder.class).userException = exception;

        assertEquals(expected, failureReason(authenticate()));
    }

    @ParameterizedTest(name = "{0} during the manager bind yields UNKNOWN")
    @MethodSource("managerBindFailures")
    void exceptionDuringTheManagerBindNeverBlamesTheCredentials(NamingException exception) {
        context.getBean(FailingContextBuilder.class).managerException = exception;

        assertEquals(AuthenticationFailureReason.UNKNOWN, failureReason(authenticate()));
    }

    @ParameterizedTest(name = "{0} while searching with the manager context yields UNKNOWN")
    @MethodSource("searchFailures")
    void exceptionWhileSearchingWithTheManagerContextNeverBlamesTheCredentials(NamingException exception) {
        context.getBean(FailingLdapSearchService.class).exception = exception;

        assertEquals(AuthenticationFailureReason.UNKNOWN, failureReason(authenticate()));
    }

    static Stream<Arguments> groupSearchFailures() {
        return Stream.of(
                Arguments.of(new javax.naming.AuthenticationException("referral bind rejected"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new AuthenticationNotSupportedException("not supported"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new OperationNotSupportedException("[LDAP: error code 53]"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new NoPermissionException("[LDAP: error code 50]"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new CommunicationException("connection reset"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                Arguments.of(new ServiceUnavailableException("unavailable"), AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        );
    }

    @ParameterizedTest(name = "{0} during the group search yields {1}")
    @MethodSource("groupSearchFailures")
    void exceptionDuringTheGroupSearchYieldsCredentialsDoNotMatch(NamingException exception, AuthenticationFailureReason expected) {
        context.getBean(FailingLdapSearchService.class).groupException = exception;

        assertEquals(expected, failureReason(authenticate()));
    }

    @ParameterizedTest(name = "{0} during the group search gives the same reason as a wrong password")
    @MethodSource("groupSearchFailures")
    void failingGroupSearchDoesNotRevealThatThePasswordWasCorrect(NamingException exception, AuthenticationFailureReason ignored) {
        // only the correct password reaches the group search, so its failure must read like a wrong password
        AuthenticationFailureReason wrongPassword = failureReason(LdapTestSupport.provider(context)
                .authenticate(null, LdapTestSupport.request("riemann", "wrong-password")));
        context.getBean(FailingLdapSearchService.class).groupException = exception;

        assertEquals(wrongPassword, failureReason(authenticate()));
    }

    @Test
    void userAuthenticatesWhenNothingFails() {
        assertTrue(authenticate().isAuthenticated());
    }

    private static AuthenticationResponse authenticate() {
        return LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request("riemann"));
    }

    /**
     * Delegates to the default context builder unless an exception has been configured for the manager or user bind.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultContextBuilder.class)
    @Singleton
    static class FailingContextBuilder extends DefaultContextBuilder {

        final AtomicInteger opened = new AtomicInteger();
        final AtomicInteger closed = new AtomicInteger();
        volatile NamingException managerException;
        volatile NamingException userException;

        @Override
        public DirContext build(ContextSettings contextSettings) throws NamingException {
            NamingException exception = LdapTestSupport.MANAGER_DN.equals(contextSettings.getDn()) ? managerException : userException;
            if (exception != null) {
                throw exception;
            }
            DirContext context = super.build(contextSettings);
            opened.incrementAndGet();
            return context;
        }

        @Override
        public void close(DirContext context) {
            if (context != null) {
                closed.incrementAndGet();
            }
            super.close(context);
        }
    }

    /**
     * Delegates to the default search service unless an exception has been configured for the user search or for the
     * group search.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultLdapSearchService.class)
    @Singleton
    static class FailingLdapSearchService extends DefaultLdapSearchService {

        volatile NamingException exception;
        volatile NamingException groupException;

        @Override
        public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
            if (exception != null) {
                throw exception;
            }
            // super.search, not search: the group search exception must not fail the user search
            return super.search(managerContext, settings).stream().findFirst();
        }

        @Override
        public List<LdapSearchResult> search(DirContext managerContext, SearchSettings settings) throws NamingException {
            if (groupException != null) {
                throw groupException;
            }
            return super.search(managerContext, settings);
        }
    }
}
