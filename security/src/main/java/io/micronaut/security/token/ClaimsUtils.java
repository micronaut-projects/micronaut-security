/*
 * Copyright 2017-2024 original authors
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
import org.jspecify.annotations.NonNull;

/**
 * Utility class to compare claims.
 * @author Sergio del Amo
 * @since 4.12.0
 */
@Internal
public final class ClaimsUtils {
    private static final String HTTP = "http://";
    private static final String HTTPS = "https://";
    private static final String SLASH = "/";

    private ClaimsUtils() {
    }

    /**
     * Compares an expected (configured) issuer with an issuer claim found in a token requiring an exact match
     * after normalisation. A value that starts with an {@code http://} or {@code https://} scheme (case-insensitive)
     * is normalised by removing the scheme and, when the value has no query ({@code ?}) and no fragment ({@code #}), a
     * single trailing slash; the rest (host, port, userinfo, path, query and fragment) is compared case-sensitively. Any other value is an opaque {@code StringOrURI} (RFC 7519, section 2) and is compared
     * verbatim: no case folding and no trailing slash removal, so {@code TenantA} and {@code tenanta} are different
     * issuers. No suffix or parent-domain matching is performed: an empty claim, a top-level domain, a registrable
     * domain, a parent domain of the expected host or a path-only suffix never matches.
     * <p>
     * The scheme tolerance exists for compatibility with {@code micronaut.security.token.jwt.claims-validators.issuer};
     * OpenID Connect ID tokens are compared with {@link IssuerUtils#equivalent(String, String)}, which requires the scheme.
     * @param expectedClaim Expected Claim
     * @param claim Claim
     * @return Whether the claim is equal to the expected claim after normalisation.
     * @since 5.5.2
     */
    public static boolean equalsIgnoringProtocolAndTrailingSlash(@NonNull String expectedClaim, @NonNull String claim) {
        String actual = normalize(claim);
        return !actual.isEmpty() && normalize(expectedClaim).equals(actual);
    }

    /**
     * Compares an expected (configured) issuer with an issuer claim found in a token.
     * @param expectedClaim Expected Claim
     * @param claim Claim
     * @return Whether the claim is equal to the expected claim after normalisation.
     * @deprecated Use {@link #equalsIgnoringProtocolAndTrailingSlash(String, String)} instead. This method no longer performs a suffix match.
     */
    @Deprecated(since = "5.5.2", forRemoval = true)
    public static boolean endsWithIgnoringProtocolAndTrailingSlash(@NonNull String expectedClaim, @NonNull String claim) {
        return equalsIgnoringProtocolAndTrailingSlash(expectedClaim, claim);
    }

    /**
     * For example for input {@code https://identity.oraclecloud.com/}, it returns {@code identity.oraclecloud.com}.
     * Only a leading {@code http://} or {@code https://} scheme and a single trailing slash are removed; the slash is kept
     * when the value has a query or a fragment, where it is part of that component.
     * @param claim Token Claim
     * @return Token Claim without leading protocol and trailing slash
     */
    @NonNull
    static String removeLeadingProtocolAndTrailingSlash(@NonNull String claim) {
        return removeTrailingSlash(removeLeadingProtocol(claim));
    }

    /**
     * For a value with a leading {@code http://} or {@code https://} scheme, removes the scheme and a single trailing slash.
     * Any other value is returned as is.
     * @param claim Token Claim
     * @return normalised claim
     */
    @NonNull
    private static String normalize(@NonNull String claim) {
        return hasHttpScheme(claim) ? removeLeadingProtocolAndTrailingSlash(claim) : claim;
    }

    private static boolean hasHttpScheme(@NonNull String iss) {
        return httpSchemeLength(iss) > 0;
    }

    /**
     * @param iss Token Claim
     * @return the length of the leading {@code http://} or {@code https://} scheme, compared ignoring ASCII case only, or {@code -1}
     */
    private static int httpSchemeLength(@NonNull String iss) {
        if (startsWithAsciiIgnoreCase(iss, HTTPS)) {
            return HTTPS.length();
        }
        if (startsWithAsciiIgnoreCase(iss, HTTP)) {
            return HTTP.length();
        }
        return -1;
    }

    /**
     * ASCII-only case-insensitive prefix test. {@link String#regionMatches(boolean, int, String, int, int)} folds Unicode
     * case as well, which would accept {@code httpſ://} (U+017F LATIN SMALL LETTER LONG S) as {@code https://}.
     * @param value the value
     * @param prefix a lower-case ASCII prefix
     * @return whether {@code value} starts with {@code prefix} ignoring ASCII case
     */
    private static boolean startsWithAsciiIgnoreCase(@NonNull String value, @NonNull String prefix) {
        if (value.length() < prefix.length()) {
            return false;
        }
        for (int i = 0; i < prefix.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            }
            if (c != prefix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    @NonNull
    private static String removeTrailingSlash(@NonNull String iss) {
        if (!iss.endsWith(SLASH) || iss.indexOf('?') != -1 || iss.indexOf('#') != -1) {
            return iss;
        }
        return iss.substring(0, iss.length() - SLASH.length());
    }

    @NonNull
    private static String removeLeadingProtocol(@NonNull String iss) {
        int length = httpSchemeLength(iss);
        return length > 0 ? iss.substring(length) : iss;
    }
}
