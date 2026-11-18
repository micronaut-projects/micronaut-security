/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.ldap.context;

import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import jakarta.inject.Singleton;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Warns once, when an enabled {@link LdapConfiguration} is created, about attribute settings
 * that conflict with its excluded attributes.
 */
@Singleton
@Internal
final class ExcludedAttributesConflictListener implements BeanCreatedEventListener<LdapConfiguration> {

    private static final Logger LOG = LoggerFactory.getLogger(ExcludedAttributesConflictListener.class);

    @Override
    public LdapConfiguration onCreated(BeanCreatedEvent<LdapConfiguration> event) {
        LdapConfiguration configuration = event.getBean();
        if (configuration.isEnabled()) {
            warnAboutExcludedAttributes(configuration);
        }
        return configuration;
    }

    private static void warnAboutExcludedAttributes(LdapConfiguration configuration) {
        LdapConfiguration.SearchConfiguration search = configuration.getSearch();
        LdapConfiguration.GroupConfiguration groups = configuration.getGroups();
        String[] requested = search.getAttributes();
        Optional<String> groupFilterAttribute = groups.isEnabled() ? groups.getFilterAttribute() : Optional.empty();
        for (String excluded : new HashSet<>(search.getExcludedAttributes())) {
            if (requested != null && Arrays.stream(requested).anyMatch(attribute -> matches(attribute, excluded))) {
                LOG.warn("LDAP configuration [{}] requests search attribute [{}], but search.excluded-attributes removes it. "
                    + "Remove it from search.excluded-attributes if the application needs it.", configuration.getName(), excluded);
            }
            if (groupFilterAttribute.filter(attribute -> matches(attribute, excluded)).isPresent()) {
                LOG.warn("LDAP configuration [{}] uses groups.filter-attribute [{}], but search.excluded-attributes removes it. "
                    + "Group resolution requires removing it from search.excluded-attributes and including it in search.attributes when configured.", configuration.getName(), excluded);
            }
        }
    }

    private static boolean matches(@Nullable String attribute, String excluded) {
        return attribute != null && LdapAttributeUtils.matchesExclusion(attribute.trim(), excluded);
    }
}
