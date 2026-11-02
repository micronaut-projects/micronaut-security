package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import io.micronaut.context.ApplicationContext
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.ldap.configuration.LdapConfiguration

class LdapSearchExcludedAttributesSpec extends InMemoryLdapSpec {

    private static final String SPEC_NAME = 'LdapSearchExcludedAttributesSpec'

    private static Map<String, Object> baseConfig(InMemoryDirectoryServer s) {
        [
                'spec.name': SPEC_NAME,
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}".toString(),
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.default.groups.enabled': true,
                'micronaut.security.ldap.default.groups.base': "dc=example,dc=com",
        ]
    }

    private static Set<String> lowerCaseAttributeNames(AuthenticationResponse response) {
        response.authentication.get().attributes.keySet().collect { it.toLowerCase() } as Set<String>
    }

    void "excluded attributes default to userPassword and unicodePwd"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.context.server': "ldap://localhost:1389",
        ], "test")

        expect:
        ctx.getBean(LdapConfiguration).search.excludedAttributes == ['userPassword', 'unicodePwd']
        ctx.getBean(LdapConfiguration).search.attributes == null

        cleanup:
        ctx.close()
    }

    void "userPassword is stripped from the search result by default"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run(baseConfig(s), "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated
        response.authentication.get().name == "riemann"
        response.authentication.get().roles as List == ['Mathematicians']

        when:
        Set<String> names = lowerCaseAttributeNames(response)

        then:
        names.contains('uid')
        names.contains('cn')
        names.contains('sn')
        !names.contains('userpassword')

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "userPassword is returned when excluded-attributes is cleared"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run(baseConfig(s) + [
                'micronaut.security.ldap.default.search.excluded-attributes': [],
        ], "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        expect:
        ctx.getBean(LdapConfiguration).search.excludedAttributes.isEmpty()

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated
        response.authentication.get().roles as List == ['Mathematicians']

        when:
        Set<String> names = lowerCaseAttributeNames(response)

        then:
        names.contains('uid')
        names.contains('userpassword')

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "excluded-attributes can be extended with additional attributes"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run(baseConfig(s) + [
                'micronaut.security.ldap.default.search.excluded-attributes': ['userPassword', 'SN'],
        ], "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated

        when:
        Set<String> names = lowerCaseAttributeNames(response)

        then:
        names.contains('uid')
        names.contains('cn')
        !names.contains('sn')
        !names.contains('userpassword')

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "an explicit attributes list restricts the returned attributes"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run(baseConfig(s) + [
                'micronaut.security.ldap.default.search.attributes': ['cn', 'sn'],
        ], "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated
        response.authentication.get().name == "riemann"
        response.authentication.get().roles as List == ['Mathematicians']

        when:
        Set<String> names = lowerCaseAttributeNames(response)

        then:
        names == ['cn', 'sn'] as Set

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "an excluded attribute is stripped even when requested explicitly"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run(baseConfig(s) + [
                'micronaut.security.ldap.default.search.attributes': ['cn', 'userPassword'],
        ], "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, "riemann")

        then:
        response.authenticated
        lowerCaseAttributeNames(response) == ['cn'] as Set

        cleanup:
        ctx.close()
        s.shutDown(true)
    }
}
