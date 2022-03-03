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
package io.micronaut.security.ldap.group;

import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.SearchProvider;
import jakarta.inject.Singleton;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link LdapGroupProcessor}.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class DefaultLdapGroupProcessor implements LdapGroupProcessor {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultLdapGroupProcessor.class);

    @Override
    public Set<String> process(String attribute, LdapSearchResult result, SearchProvider groupResults) throws NamingException {
        Set<String> groupSet = new HashSet<>();

        List<LdapSearchResult> groupSearch = groupResults.get();

        if (groupSearch.isEmpty() && LOG.isDebugEnabled()) {
            LOG.debug("No groups found!");
        }

        for (LdapSearchResult groupResult: groupSearch) {
            groupResult.getAttributes()
                    .get(attribute, List.class)
                    .ifPresent(groups -> {
                        for (Object group: groups) {
                            processGroup(group.toString()).ifPresent(groupSet::add);
                        }
                    });

            if (LOG.isTraceEnabled()) {
                LOG.trace("The following groups were found for [{}]: {}", result.getDn(), groupSet);
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Attempting to add any additional groups...");
        }

        groupSet.addAll(getAdditionalGroups(result));

        return groupSet;
    }
}
