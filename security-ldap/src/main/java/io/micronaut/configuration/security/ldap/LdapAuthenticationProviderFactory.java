package io.micronaut.configuration.security.ldap;

import io.micronaut.configuration.security.ldap.configuration.LdapConfiguration;
import io.micronaut.configuration.security.ldap.context.ContextBuilder;
import io.micronaut.configuration.security.ldap.context.LdapSearchService;
import io.micronaut.configuration.security.ldap.group.LdapGroupProcessor;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;

/**
 * Factory to create an LDAP authentication provider if the configuration is enabled.
 *
 * @author Álvaro Sánchez-Mariscal
 * @since 1.2.3
 */
@Factory
public class LdapAuthenticationProviderFactory {

    /**
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @return an {@link LdapAuthenticationProvider} if the corresponding {@link LdapConfiguration} is enabled
     */
    @EachBean(LdapConfiguration.class)
    public LdapAuthenticationProvider ldapAuthenticationProvider(@Parameter LdapConfiguration configuration,
                                                                           LdapSearchService ldapSearchService,
                                                                           ContextBuilder contextBuilder,
                                                                           ContextAuthenticationMapper contextAuthenticationMapper,
                                                                           LdapGroupProcessor ldapGroupProcessor) {
        if (configuration.isEnabled()) {
            return new LdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
        } else {
            return null;
        }
    }
}
