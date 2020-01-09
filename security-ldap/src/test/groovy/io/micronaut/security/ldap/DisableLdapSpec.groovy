package io.micronaut.security.ldap

import io.micronaut.configuration.security.ldap.LdapAuthenticationProvider
import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.inject.qualifiers.Qualifiers
import spock.lang.Specification

class DisableLdapSpec extends Specification {

    void "LDAP support can be globally disabled"() {
        given:
        def ctx = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.ldap.enabled': false,
                'micronaut.security.ldap.basic.enabled': true
        ], "test")

        when:
        ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('basic'))

        then:
        thrown(NoSuchBeanException)
    }

    void "LDAP support can be disabled on a provider basis"() {
        given:
        def ctx = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.ldap.enabled': true,
                'micronaut.security.ldap.basic.enabled': false,
                'micronaut.security.ldap.advanced.enabled': true
        ], "test")

        when:
        ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('basic'))

        then:
        thrown(NoSuchBeanException)

        when:
        LdapAuthenticationProvider provider = ctx.getBean(LdapAuthenticationProvider, Qualifiers.byName('advanced'))

        then:
        provider
    }



}
