package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The directory answers a bind with an LDAP result code, which JNDI turns into a
 * {@link javax.naming.NamingException} subclass. These tests make the directory answer with a
 * given result code, so that the whole chain from the code on the wire to the
 * {@link AuthenticationFailureReason} is exercised, not only the mapping of the exception.
 */
class LdapBindResultCodeTest {

    private static final String USER = "riemann";
    private static final String USER_DN = "uid=riemann,dc=example,dc=com";

    private static final Map<String, ResultCode> BIND_RESULTS = new ConcurrentHashMap<>();

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;

    @BeforeAll
    static void setup() throws Exception {
        server = LdapTestSupport.startServer("basic.ldif", new InMemoryOperationInterceptor() {
            @Override
            public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                ResultCode resultCode = BIND_RESULTS.get(request.getRequest().getBindDN());
                if (resultCode != null) {
                    // the in-memory directory answers the bind with the result code of the exception
                    throw new LDAPException(resultCode, "simulated " + resultCode.getName());
                }
            }
        });
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

    @AfterEach
    void resetBindResults() {
        BIND_RESULTS.clear();
    }

    @ParameterizedTest(name = "result code {0} ({1}) to the user bind yields {2}")
    @CsvSource({
            "7,  authMethodNotSupported,       CREDENTIALS_DO_NOT_MATCH",
            "8,  strongerAuthRequired,         CREDENTIALS_DO_NOT_MATCH",
            "12, unavailableCriticalExtension, CREDENTIALS_DO_NOT_MATCH",
            "13, confidentialityRequired,      CREDENTIALS_DO_NOT_MATCH",
            "48, inappropriateAuthentication,  CREDENTIALS_DO_NOT_MATCH",
            "49, invalidCredentials,           CREDENTIALS_DO_NOT_MATCH",
            "53, unwillingToPerform,           CREDENTIALS_DO_NOT_MATCH",
            "51, busy,                         UNKNOWN",
            "52, unavailable,                  UNKNOWN",
            "80, other,                        UNKNOWN",
    })
    void resultCodeOfTheUserBindDecidesTheFailureReason(int resultCode, String name, AuthenticationFailureReason expected) {
        BIND_RESULTS.put(USER_DN, ResultCode.valueOf(resultCode));

        assertEquals(expected, failureReason(authenticate()), name);
    }

    @ParameterizedTest(name = "result code {0} ({1}) to the manager bind yields UNKNOWN")
    @CsvSource({
            "8,  strongerAuthRequired",
            "49, invalidCredentials",
            "53, unwillingToPerform",
    })
    void resultCodeOfTheManagerBindNeverBlamesTheCredentials(int resultCode, String name) {
        BIND_RESULTS.put(LdapTestSupport.MANAGER_DN, ResultCode.valueOf(resultCode));

        assertEquals(AuthenticationFailureReason.UNKNOWN, failureReason(authenticate()), name);
    }

    @Test
    void userAuthenticatesWhenNoBindIsRejected() {
        assertTrue(authenticate().isAuthenticated());
    }

    private static AuthenticationFailureReason failureReason(AuthenticationResponse response) {
        assertFalse(response.isAuthenticated());
        return assertInstanceOf(AuthenticationFailed.class, response).getReason();
    }

    @SuppressWarnings("unchecked")
    private static AuthenticationResponse authenticate() {
        LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);
        return provider.authenticate(null, LdapTestSupport.request(USER));
    }
}
