package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import io.micronaut.context.ApplicationContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.AuthenticationResponse
import reactor.test.StepVerifier

class LdapAuthenticationSpec extends InMemoryLdapSpec {

    void "test authentication and role retrieval with uniquemember"() {
        given:
        def s = createServer("basic.ldif")
        s.startListening()
        def ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.default.groups.enabled': true,
                'micronaut.security.ldap.default.groups.base': "dc=example,dc=com",
        ], "test")

        when:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)
        AuthenticationResponse response = authenticate(authenticationProvider,"riemann")

        then:
        response.authenticated
        response.authentication.isPresent()
        response.authentication.get().name == "riemann"
        response.authentication.get().roles.size() == 1
        response.authentication.get().roles.contains("Mathematicians")

        when:
        response = authenticate(authenticationProvider,"newton")

        then:
        response.authenticated
        response.authentication.isPresent()
        response.authentication.get().name == "newton"
        response.authentication.get().roles.size() == 1
        response.authentication.get().roles.contains("Scientists")


        when:
        response = authenticate(authenticationProvider,"gauss")

        then:
        response.authenticated
        response.authentication.isPresent()
        response.authentication.get().name == "gauss"
        response.authentication.get().roles.size() == 2
        response.authentication.get().roles.contains("Scientists")
        response.authentication.get().roles.contains("Mathematicians")

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test authentication without group configuration"() {
        given:
        def s = createServer("basic.ldif")
        s.startListening()
        def ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
        ], "test")

        when:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)
        AuthenticationResponse response = authenticate(authenticationProvider,"riemann")

        then:
        response.authenticated
        response.authentication.isPresent()
        response.authentication.get().name == "riemann"
        !response.authentication.get().roles

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test authentication without search configuration"() {
        given:
        def s = createServer("basic.ldif")
        s.startListening()
        def ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
        ], "test")

        when:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)
        AuthenticationResponse response = authenticate(authenticationProvider,"riemann")

        then:
        response.authenticated
        response.authentication.isPresent()
        response.authentication.get().name == "riemann"
        !response.authentication.get().roles

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test authentication and role retrieval with member"() {
        given:
        def s = createServer("member.ldif")
        s.startListening()
        def ctx = ApplicationContext.run([
                'micronaut.security.ldap.foo.enabled': true,
                'micronaut.security.ldap.foo.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.foo.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.foo.context.managerPassword': "password",
                'micronaut.security.ldap.foo.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.foo.groups.enabled': true,
                'micronaut.security.ldap.foo.groups.base': "ou=groups,dc=example,dc=com",
                'micronaut.security.ldap.foo.groups.filter': "member={0}",
        ], "test")

        when:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('foo'))
        AuthenticationResponse response = authenticate(authenticationProvider,"euclid")

        then:
        response.authenticated
        response.authentication.get().name == "euclid"
        response.authentication.get().roles.size() == 1
        response.authentication.get().roles.contains("users")

        when:
        response = authenticate(authenticationProvider,"gauss")

        then:
        response.authenticated
        response.authentication.get().name == "gauss"
        response.authentication.get().roles.size() == 2
        response.authentication.get().roles.contains("users")
        response.authentication.get().roles.contains("admins")

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test authenticating with a username that doesn't exist"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.default.groups.enabled': true,
                'micronaut.security.ldap.default.groups.base': "dc=example,dc=com",
        ])
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        expect:
        StepVerifier.create(authenticationProvider.authenticate(null, createAuthenticationRequest("abc", "password")))
                .expectErrorMessage("User Not Found")
                .verify()

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test authenticating with an invalid password"() {
        given:
        InMemoryDirectoryServer s = createServer("basic.ldif")
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.default.groups.enabled': true,
                'micronaut.security.ldap.default.groups.base': "dc=example,dc=com",
        ])
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)

        expect:
        StepVerifier.create(authenticationProvider.authenticate(null, createAuthenticationRequest("euclid", "abc")))
                .expectErrorMessage("Credentials Do Not Match")
                .verify()

        cleanup:
        ctx.close()
        s.shutDown(true)
    }

    void "test configuring multiple servers"() {
        given:
        def s = createServer("basic.ldif")
        def s2 = createServer("member.ldif")
        s.startListening()
        s2.startListening()
        def ctx = ApplicationContext.run([
                'micronaut.security.ldap.basic.enabled': true,
                'micronaut.security.ldap.basic.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.basic.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.basic.context.managerPassword': "password",
                'micronaut.security.ldap.basic.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.basic.groups.enabled': true,
                'micronaut.security.ldap.basic.groups.base': "dc=example,dc=com",
                'micronaut.security.ldap.member.enabled': true,
                'micronaut.security.ldap.member.context.server': "ldap://localhost:${s2.listenPort}",
                'micronaut.security.ldap.member.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.member.context.managerPassword': "password",
                'micronaut.security.ldap.member.search.base': "dc=example,dc=com",
                'micronaut.security.ldap.member.groups.enabled': true,
                'micronaut.security.ldap.member.groups.base': "ou=groups,dc=example,dc=com",
                'micronaut.security.ldap.member.groups.filter': "member={0}",
        ], "test")

        when:
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('member'))
        AuthenticationResponse response = authenticate(authenticationProvider,"gauss")

        then:
        response.authenticated
        response.authentication.get().name == "gauss"
        response.authentication.get().roles.size() == 2
        response.authentication.get().roles.contains("users")
        response.authentication.get().roles.contains("admins")

        when:
        authenticationProvider = ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('basic'))
        response = authenticate(authenticationProvider,"gauss")

        then:
        response.authenticated
        response.authentication.get().name == "gauss"
        response.authentication.get().roles.size() == 2
        response.authentication.get().roles.contains("Scientists")
        response.authentication.get().roles.contains("Mathematicians")

        cleanup:
        ctx.close()
        s.shutDown(true)
        s2.shutDown(true)
    }

}
