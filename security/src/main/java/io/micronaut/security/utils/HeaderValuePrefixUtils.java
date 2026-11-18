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
package io.micronaut.security.utils;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import org.jspecify.annotations.Nullable;

/**
 * Utility methods to add a prefix, such as {@code Bearer}, to an HTTP header value or remove it.
 *
 * @author Sergio del Amo
 * @since 5.5.3
 */
@Internal
public final class HeaderValuePrefixUtils {

    private static final char SPACE = ' ';

    private HeaderValuePrefixUtils() {
    }

    /**
     * Removes the prefix and the single space after it from the header value.
     * The prefix is compared ignoring case. Only one space is removed, so the token may be empty or start with a space.
     * A prefix which already ends with a space is not followed by another one.
     * If the prefix is {@code null} or empty, the whole header value is the token.
     *
     * @param headerValue The header value. e.g. {@code Bearer XXX}
     * @param prefix The prefix before the token. e.g. {@code Bearer}
     * @return The token, e.g. {@code XXX}. {@code null} if the header value does not start with the prefix and a space.
     */
    @Nullable
    public static String removePrefix(String headerValue, @Nullable String prefix) {
        if (StringUtils.isEmpty(prefix)) {
            return headerValue;
        }
        final int prefixLength = prefix.length();
        final boolean prefixEndsWithSpace = prefix.charAt(prefixLength - 1) == SPACE;
        final int tokenStart = prefixEndsWithSpace ? prefixLength : prefixLength + 1;
        if (headerValue.length() >= tokenStart
                && (prefixEndsWithSpace || headerValue.charAt(prefixLength) == SPACE)
                && startsWithIgnoreCase(headerValue, prefix)) {
            return headerValue.substring(tokenStart);
        }
        return null;
    }

    /**
     * Adds the prefix and a space before the token. A prefix which already ends with a space is not followed by another one.
     * If the prefix is {@code null} or empty, the token is returned as is.
     *
     * @param token The token. e.g. {@code XXX}
     * @param prefix The prefix before the token. e.g. {@code Bearer}
     * @return The header value. e.g. {@code Bearer XXX}
     */
    public static String addPrefix(String token, @Nullable String prefix) {
        if (StringUtils.isEmpty(prefix)) {
            return token;
        }
        return prefix.charAt(prefix.length() - 1) == SPACE ? prefix + token : prefix + SPACE + token;
    }

    /**
     * Compares characters by their lower-case form only. {@link String#regionMatches(boolean, int, String, int, int)}
     * also folds through upper case, which would accept look-alikes such as {@code "Baſıc"} for {@code "Basic"}.
     *
     * @param value  The value to test. It must be at least as long as the prefix.
     * @param prefix The expected prefix
     * @return Whether the value starts with the prefix, ignoring case
     */
    private static boolean startsWithIgnoreCase(String value, String prefix) {
        for (int i = 0; i < prefix.length(); i++) {
            char expected = prefix.charAt(i);
            char actual = value.charAt(i);
            if (expected != actual && Character.toLowerCase(expected) != Character.toLowerCase(actual)) {
                return false;
            }
        }
        return true;
    }
}
