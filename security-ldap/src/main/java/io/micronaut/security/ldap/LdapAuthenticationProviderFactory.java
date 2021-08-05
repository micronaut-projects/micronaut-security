/*
 * Copyright 2017-2020 original authors
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

import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.TaskExecutors;

import jakarta.inject.Named;
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
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @param executorService             Executor Service
     * @return an {@link LdapAuthenticationProvider} if the corresponding {@link LdapConfiguration} is enabled
     */
    @EachBean(LdapConfiguration.class)
    @Requires(condition = LdapEnabledCondition.class)
    public LdapAuthenticationProvider ldapAuthenticationProvider(@Parameter LdapConfiguration configuration,
                                                                 LdapSearchService ldapSearchService,
                                                                 ContextBuilder contextBuilder,
                                                                 ContextAuthenticationMapper contextAuthenticationMapper,
                                                                 LdapGroupProcessor ldapGroupProcessor,
                                                                 @Named(TaskExecutors.IO) ExecutorService executorService) {
        return new LdapAuthenticationProvider(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor, executorService);
    }
}
