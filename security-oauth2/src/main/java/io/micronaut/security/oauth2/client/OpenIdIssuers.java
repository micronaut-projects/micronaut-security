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
package io.micronaut.security.oauth2.client;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;

/**
 * Compares OpenID issuer identifiers.
 *
 * @since 5.5.2
 */
@Internal
public final class OpenIdIssuers {

    private OpenIdIssuers() {
    }

    /**
     * Compares two issuers. They are equal if they are identical, ignoring the case of the scheme (folded for ASCII only)
     * and a single trailing slash. Nothing else is tolerated: the host, port, userinfo and path must be identical, and
     * a different scheme or a missing scheme is a mismatch.
     *
     * @param expected The expected issuer
     * @param actual The issuer to compare
     * @return true if both issuers are equal
     */
    public static boolean equivalent(@Nullable String expected, @Nullable String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        String a = normalize(expected);
        String b = normalize(actual);
        return !a.isEmpty() && a.equals(b);
    }

    private static String normalize(String issuer) {
        String value = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        int index = value.indexOf("://");
        if (index <= 0) {
            return value;
        }
        StringBuilder scheme = new StringBuilder(index);
        for (int i = 0; i < index; i++) {
            char c = value.charAt(i);
            scheme.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
        }
        return scheme + value.substring(index);
    }
}
