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
package io.micronaut.security.token;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;

/**
 * Utility class to compare issuers, such as the {@code iss} claim of a token against the issuer expected for a key set or an OpenID client.
 * <p>
 * Unlike {@link ClaimsUtils#equalsIgnoringProtocolAndTrailingSlash(String, String)}, a missing scheme or a different scheme is a
 * mismatch ({@code http://} is not {@code https://}), as OpenID Connect Core 1.0 section 3.1.3.7 requires; no suffix or
 * parent domain is tolerated either. It is meant to run on untrusted input before a token is verified, so it allocates no state per
 * distinct value.
 *
 * @author Sergio del Amo
 * @since 5.5.2
 */
@Internal
public final class IssuerUtils {

    private IssuerUtils() {
    }

    /**
     * Compares two issuers. They are equal if they are identical, ignoring the case of the scheme (folded for ASCII only)
     * and a single trailing slash. The slash is only ignored when the issuer has no query ({@code ?}) and no fragment
     * ({@code #}), where it would be part of that component. Nothing else is tolerated: the host, port, userinfo, path,
     * query and fragment must be identical, and a different scheme or a missing scheme is a mismatch.
     *
     * @param expected The expected issuer
     * @param actual The issuer to compare
     * @return {@code true} if both issuers are non-null, non-empty and equal
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
        boolean stripSlash = issuer.endsWith("/") && issuer.indexOf('?') == -1 && issuer.indexOf('#') == -1;
        String value = stripSlash ? issuer.substring(0, issuer.length() - 1) : issuer;
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
