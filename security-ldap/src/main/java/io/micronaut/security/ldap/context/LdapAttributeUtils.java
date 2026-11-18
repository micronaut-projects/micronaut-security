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
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
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
     * every option variant of that attribute type; an exclusion with options matches the same option set,
     * regardless of order. The names and OIDs of the two default password attributes are treated as aliases.
     *
     * @param attributeId The returned or configured attribute description
     * @param excludedAttribute The excluded attribute name or description
     * @return Whether the exclusion matches
     */
    static boolean matchesExclusion(String attributeId, String excludedAttribute) {
        if (excludedAttribute.equalsIgnoreCase(attributeId)) {
            return true;
        }
        int attributeOptions = attributeId.indexOf(';');
        int excludedOptions = excludedAttribute.indexOf(';');
        if (!canonicalType(attributeId, attributeOptions).equalsIgnoreCase(canonicalType(excludedAttribute, excludedOptions))) {
            return false;
        }
        return excludedOptions < 0 || attributeOptions >= 0
            && options(attributeId, attributeOptions).equals(options(excludedAttribute, excludedOptions));
    }

    private static String canonicalType(String description, int optionsStart) {
        String type = optionsStart < 0 ? description : description.substring(0, optionsStart);
        return switch (type) {
            case "2.5.4.35" -> "userPassword";
            case "1.2.840.113556.1.4.90" -> "unicodePwd";
            default -> type;
        };
    }

    private static Set<String> options(String description, int optionsStart) {
        Set<String> options = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        options.addAll(Arrays.asList(description.substring(optionsStart + 1).split(";")));
        return options;
    }
}
