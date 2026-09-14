package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import io.micronaut.context.ApplicationContext
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.authentication.AuthenticationResponse
import spock.lang.AutoCleanup
import spock.lang.Shared

/**
 * Verifies that the factory-created {@link LdapAuthenticationProvider} runs on the blocking executor and authenticates.
 */
class LdapAuthenticationProviderExecutorSpec extends InMemoryLdapSpec {

    @Shared
    InMemoryDirectoryServer server

    @Shared
    @AutoCleanup
    ApplicationContext ctx

    def setupSpec() {
        server = createServer("basic.ldif")
        server.startListening()
        ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${server.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
        ], "test")
    }

    def cleanupSpec() {
        server?.shutDown(true)
    }

    void "the LDAP authentication provider runs on the blocking executor"() {
        expect:
        ctx.getBeansOfType(LdapAuthenticationProvider).size() == 1
        ctx.getBean(LdapAuthenticationProvider).executorName == TaskExecutors.BLOCKING
    }

    void "the factory-created LDAP authentication provider authenticates"() {
        when:
        AuthenticationResponse response = authenticate(ctx.getBean(LdapAuthenticationProvider), "riemann")

        then:
        response.authenticated
        response.authentication.get().name == "riemann"
    }
}
