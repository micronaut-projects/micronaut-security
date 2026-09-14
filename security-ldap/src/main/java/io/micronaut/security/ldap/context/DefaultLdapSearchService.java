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
package io.micronaut.security.ldap.context;

import io.micronaut.core.util.CollectionUtils;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * Default implementation of {@link LdapSearchService}.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class DefaultLdapSearchService implements LdapSearchService {

    @Override
    public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
        List<LdapSearchResult> results = search(managerContext, settings);
        if (results.size() > 0) {
            LdapSearchResult result = results.get(0);
            return Optional.of(result);
        }
        return Optional.empty();
    }

    @Override
    public List<LdapSearchResult> search(DirContext managerContext, SearchSettings settings) throws NamingException {
        SearchControls ctrls = new SearchControls();
        ctrls.setReturningAttributes(settings.getAttributes());
        if (settings.isSubtree()) {
            ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        }
        NamingEnumeration<SearchResult> results = managerContext.search(settings.getBase(), settings.getFilter(), settings.getArguments(), ctrls);
        return createResults(results, settings.getExcludedAttributes());
    }

    /**
     * Builds {@link LdapSearchResult} from the LDAP results without stripping any attribute.
     *
     * @param results The LDAP results
     * @return The list of {@link LdapSearchResult}
     * @throws NamingException If an error occurs
     */
    protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> results) throws NamingException {
        return createResults(results, Collections.emptyList());
    }

    /**
     * Builds {@link LdapSearchResult} from the LDAP results, stripping the excluded attributes
     * before they are wrapped into a {@link LdapSearchResult}.
     *
     * @param results            The LDAP results
     * @param excludedAttributes The attribute names to strip from every result. Matching is case-insensitive
     * @return The list of {@link LdapSearchResult}
     * @throws NamingException If an error occurs
     * @since 5.4.0
     */
    protected List<LdapSearchResult> createResults(NamingEnumeration<SearchResult> results, Collection<String> excludedAttributes) throws NamingException {
        List<LdapSearchResult> searchResults = new ArrayList<>();
        while (results.hasMore()) {
            SearchResult result = results.next();
            Attributes attributes = removeExcludedAttributes(result.getAttributes(), excludedAttributes);
            String dn = result.getNameInNamespace();

            searchResults.add(new LdapSearchResult(attributes, dn));
        }
        return searchResults;
    }

    /**
     * Removes the excluded attributes from the given {@link Attributes}.
     *
     * @param attributes         The attributes returned by LDAP. May be null
     * @param excludedAttributes The attribute names to remove. Matching is case-insensitive
     * @return The attributes without the excluded ones
     * @throws NamingException If the attribute ids cannot be enumerated
     */
    protected Attributes removeExcludedAttributes(Attributes attributes, Collection<String> excludedAttributes) throws NamingException {
        if (attributes == null || CollectionUtils.isEmpty(excludedAttributes)) {
            return attributes;
        }
        List<String> idsToRemove = new ArrayList<>();
        NamingEnumeration<String> ids = attributes.getIDs();
        try {
            while (ids.hasMore()) {
                String id = ids.next();
                if (isExcluded(id, excludedAttributes)) {
                    idsToRemove.add(id);
                }
            }
        } finally {
            ids.close();
        }
        for (String id : idsToRemove) {
            attributes.remove(id);
        }
        return attributes;
    }

    private static boolean isExcluded(String attributeId, Collection<String> excludedAttributes) {
        for (String excluded : excludedAttributes) {
            if (excluded != null && excluded.equalsIgnoreCase(attributeId)) {
                return true;
            }
        }
        return false;
    }
}
