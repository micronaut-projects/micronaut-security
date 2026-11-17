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

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NullMarked;

/**
 * Shared LDAP attribute exclusion matching for filtering and configuration diagnostics.
 */
@Internal
@NullMarked
final class LdapAttributeUtils {

    private LdapAttributeUtils() {
    }

    /**
     * Matches attribute descriptions case-insensitively. An exclusion without options covers
     * every option variant of that attribute type; an exclusion with options matches the full description.
     *
     * @param attributeId The returned or configured attribute description
     * @param excludedAttribute The excluded attribute name or description
     * @return Whether the exclusion matches
     */
    static boolean matchesExclusion(String attributeId, String excludedAttribute) {
        if (excludedAttribute.equalsIgnoreCase(attributeId)) {
            return true;
        }
        int optionsStart = attributeId.indexOf(';');
        return optionsStart > 0 && excludedAttribute.length() == optionsStart
            && attributeId.regionMatches(true, 0, excludedAttribute, 0, optionsStart);
    }
}
