package io.micronaut.security.ldap

import com.unboundid.ldap.listener.InMemoryDirectoryServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.convert.value.ConvertibleValues
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.ldap.context.AttributesConvertibleValues
import io.micronaut.security.ldap.context.DefaultLdapSearchService
import io.micronaut.security.ldap.context.LdapSearchResult
import io.micronaut.security.ldap.context.SearchSettings
import jakarta.inject.Singleton

import javax.naming.NamingException
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext

/**
 * When a custom {@link io.micronaut.security.ldap.context.LdapSearchService} returns a result without attributes,
 * {@link LdapAuthenticationProvider} fetches them with the user context. The DN must be parsed as an LDAP name, not as a
 * JNDI composite name, otherwise DNs containing characters such as '/' cannot be resolved.
 */
class LdapNameAttributesSpec extends InMemoryLdapSpec {

    void "attributes are fetched with the user context for DN #dn when the search result has none"() {
        given:
        InMemoryDirectoryServer s = createServer(ldif)
        s.startListening()
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': 'LdapNameAttributesSpec',
                'micronaut.security.ldap.default.enabled': true,
                'micronaut.security.ldap.default.context.server': "ldap://localhost:${s.listenPort}",
                'micronaut.security.ldap.default.context.managerDn': "cn=admin,dc=example,dc=com",
                'micronaut.security.ldap.default.context.managerPassword': "password",
                'micronaut.security.ldap.default.search.base': "dc=example,dc=com",
        ], "test")
        LdapAuthenticationProvider authenticationProvider = ctx.getBean(LdapAuthenticationProvider)
        NullAttributesLdapSearchService searchService = ctx.getBean(NullAttributesLdapSearchService)

        when:
        AuthenticationResponse response = authenticate(authenticationProvider, username)

        then:
        response.authenticated
        response.authentication.get().name == username
        searchService.lastResult.dn == dn
        searchService.lastResult.attributes != null
        searchService.lastResult.attributes.get("uid", String).get() == username
        searchService.lastResult.attributes.get("cn", String).get() == cn

        cleanup:
        ctx.close()
        s.shutDown(true)

        where:
        ldif         | username  | dn                              | cn
        'slash.ldif' | 'johndoe' | 'cn=John/Doe,dc=example,dc=com' | 'John/Doe'
        'basic.ldif' | 'riemann' | 'uid=riemann,dc=example,dc=com' | 'riemann'
    }

    /**
     * A search service, standing in for a custom implementation, that returns results without attributes.
     */
    @Requires(property = "spec.name", value = "LdapNameAttributesSpec")
    @Replaces(DefaultLdapSearchService)
    @Singleton
    static class NullAttributesLdapSearchService extends DefaultLdapSearchService {

        NullAttributesLdapSearchResult lastResult

        @Override
        Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
            Optional<LdapSearchResult> result = super.searchFirst(managerContext, settings)
            if (result.isPresent()) {
                lastResult = new NullAttributesLdapSearchResult(result.get().dn)
                return Optional.of(lastResult)
            }
            result
        }
    }

    /**
     * An {@link LdapSearchResult} whose attributes are null until they are populated from a non-null {@link Attributes}.
     */
    static class NullAttributesLdapSearchResult extends LdapSearchResult {

        private ConvertibleValues<Object> fetched

        NullAttributesLdapSearchResult(String dn) {
            super(null, dn)
        }

        @Override
        ConvertibleValues<Object> getAttributes() {
            fetched
        }

        @Override
        void setAttributes(Attributes attributes) {
            if (attributes != null) {
                fetched = new AttributesConvertibleValues(attributes)
            }
        }
    }
}
