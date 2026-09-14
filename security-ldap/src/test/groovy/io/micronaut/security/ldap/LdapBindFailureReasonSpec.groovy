package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.ldap.context.ContextSettings
import io.micronaut.security.ldap.context.DefaultContextBuilder
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared

import javax.naming.AuthenticationNotSupportedException
import javax.naming.CommunicationException
import javax.naming.NamingException
import javax.naming.OperationNotSupportedException
import javax.naming.ServiceUnavailableException
import javax.naming.directory.DirContext

/**
 * Verifies how {@link LdapAuthenticationProvider} maps exceptions thrown while binding to failure reasons.
 * A rejection of the user bind means the credentials were not accepted, whereas a failure of the manager bind
 * or a connectivity problem is not attributable to the user's credentials.
 */
class LdapBindFailureReasonSpec extends InMemoryLdapSpec {

    private static final String MANAGER_DN = "cn=admin,dc=example,dc=com"

    @Shared
    InMemoryDirectoryServer server

    @Shared
    @AutoCleanup
    ApplicationContext ctx

    def setupSpec() {
        server = createServer("basic.ldif")
        server.startListening()
        ctx = ApplicationContext.run([
                'spec.name': 'LdapBindFailureReasonSpec',
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${server.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': MANAGER_DN,
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
        ], "test")
    }

    def cleanupSpec() {
        server?.shutDown(true)
    }

    def cleanup() {
        ctx.getBean(FailingContextBuilder).reset()
    }

    void "#exception.class.simpleName during the #phase bind yields #reason"() {
        given:
        FailingContextBuilder contextBuilder = ctx.getBean(FailingContextBuilder)
        if (phase == 'manager') {
            contextBuilder.managerException = exception
        } else {
            contextBuilder.userException = exception
        }
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        !response.authenticated
        response instanceof AuthenticationFailed
        ((AuthenticationFailed) response).reason == reason

        where:
        phase     | exception                                                        || reason
        'user'    | new AuthenticationNotSupportedException("not supported")         || AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH
        'user'    | new OperationNotSupportedException("[LDAP: error code 53]")      || AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH
        'user'    | new javax.naming.AuthenticationException("invalid credentials")  || AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH
        'user'    | new CommunicationException("connection reset")                   || AuthenticationFailureReason.UNKNOWN
        'user'    | new ServiceUnavailableException("unavailable")                   || AuthenticationFailureReason.UNKNOWN
        'manager' | new AuthenticationNotSupportedException("not supported")         || AuthenticationFailureReason.UNKNOWN
        'manager' | new OperationNotSupportedException("[LDAP: error code 53]")      || AuthenticationFailureReason.UNKNOWN
        'manager' | new CommunicationException("connection refused")                 || AuthenticationFailureReason.UNKNOWN
    }

    void "the user is authenticated when no bind fails"() {
        given:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated
    }

    /**
     * Delegates to the default context builder unless an exception has been configured for the manager or user bind.
     */
    @Requires(property = "spec.name", value = "LdapBindFailureReasonSpec")
    @Replaces(DefaultContextBuilder)
    @Singleton
    static class FailingContextBuilder extends DefaultContextBuilder {

        NamingException managerException
        NamingException userException

        void reset() {
            managerException = null
            userException = null
        }

        @Override
        DirContext build(ContextSettings contextSettings) throws NamingException {
            NamingException exception = contextSettings.dn == MANAGER_DN ? managerException : userException
            if (exception != null) {
                throw exception
            }
            super.build(contextSettings)
        }
    }
}
