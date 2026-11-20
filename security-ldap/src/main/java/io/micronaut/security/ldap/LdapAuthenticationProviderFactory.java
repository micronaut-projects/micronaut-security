/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.ldap;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import org.jspecify.annotations.Nullable;

import java.util.concurrent.ExecutorService;

/**
 * Factory to create an LDAP authentication provider if the configuration is enabled.
 *
 * @author Álvaro Sánchez-Mariscal
 * @since 1.2.3
 */
@Factory
public class LdapAuthenticationProviderFactory {

    /**
     * Creates the provider for each enabled {@link LdapConfiguration}. Override this method to customize the provider.
     * Until the deprecated overload which takes an executor service is removed, this method delegates to it, so
     * existing overrides of that overload keep working.
     *
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @return an {@link LdapAuthenticationProvider} if the corresponding {@link LdapConfiguration} is enabled
     * @since 5.6.0
     */
    @EachBean(LdapConfiguration.class)
    @Requires(condition = LdapEnabledCondition.class)
    @SuppressWarnings("removal")
    public LdapAuthenticationProvider ldapAuthenticationProvider(@Parameter LdapConfiguration configuration,
                                                                 LdapSearchService ldapSearchService,
                                                                 ContextBuilder contextBuilder,
                                                                 ContextAuthenticationMapper contextAuthenticationMapper,
                                                                 LdapGroupProcessor ldapGroupProcessor) {
        // Delegates to the deprecated method, so that a subclass which overrides it still creates the provider.
        // Create the provider here once the deprecated method is removed.
        return ldapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor, null);
    }

    /**
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @param executorService             Ignored by this implementation. Always {@code null} when the bean factory method
     *                                    calls it; before 5.6.0 it was the {@link TaskExecutors#IO} executor. LDAP
     *                                    authentication runs on the executor named by
     *                                    {@link LdapAuthenticationProvider#getExecutorName()}, {@link TaskExecutors#BLOCKING} by default.
     * @return an {@link LdapAuthenticationProvider}
     * @deprecated The executor service is ignored. Use {@link #ldapAuthenticationProvider(LdapConfiguration, LdapSearchService, ContextBuilder, ContextAuthenticationMapper, LdapGroupProcessor)} instead.
     * Until this method is removed, the bean factory method calls it with a {@code null} executor service, so a subclass
     * that overrides it is still called. Override the method without the executor service instead, and inject an
     * executor yourself if you need one.
     */
    @Deprecated(since = "5.6.0", forRemoval = true)
    public LdapAuthenticationProvider ldapAuthenticationProvider(LdapConfiguration configuration,
                                                                 LdapSearchService ldapSearchService,
                                                                 ContextBuilder contextBuilder,
                                                                 ContextAuthenticationMapper contextAuthenticationMapper,
                                                                 LdapGroupProcessor ldapGroupProcessor,
                                                                 @Nullable ExecutorService executorService) {
        return new LdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
    }
}
