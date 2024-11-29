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
import io.micronaut.core.annotation.NonNull;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class to compare claims.
 * @author Sergio del Amo
 * @since 4.12.0
 */
@Internal
public final class ClaimsUtils {
    private static final String HTTP = "http://";
    private static final String HTTPS = "https://";
    private static final String EMPTY = "";
    private static final String SLASH = "/";

    private static final Map<ClaimPair, Boolean> cache = new HashMap<>();

    private ClaimsUtils() {
    }

    /**
     * For example, for input {@code "https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com"} and {@code identity.oraclecloud.com}, it returns {@code true}.
     * @param expectedClaim Expected Claim
     * @param claim Claim
     * @return Whether the expected claim ends with the supplied claim. Both claims are compared without leading protocol and trailing slash.
     */
    public static boolean endsWithIgnoringProtocolAndTrailingSlash(@NonNull String expectedClaim, @NonNull String claim) {
        ClaimPair pair = new ClaimPair(expectedClaim, claim);
        return cache.computeIfAbsent(pair, claimPair ->
                removeLeadingProtocolAndTrailingSlash(claimPair.expectedClaim())
                        .endsWith(removeLeadingProtocolAndTrailingSlash(claimPair.claim())));
    }

    /**
     * For example for input {@code https://identity.oraclecloud.com/}, it returns {@code identity.oraclecloud.com}.
     * @param claim Token Claim
     * @return Token Claim without leading protocol and trailing slash
     */
    @NonNull
    static String removeLeadingProtocolAndTrailingSlash(@NonNull String claim) {
        return removeTrailingSlash(removeProtocol(claim));
    }

    @NonNull
    private static String removeTrailingSlash(@NonNull String iss) {
        return iss.endsWith(SLASH) ? iss.substring(0, iss.length() - SLASH.length()) : iss;
    }

    @NonNull
    private static String removeProtocol(@NonNull String iss) {
        return iss.replace(HTTP, EMPTY)
                .replace(HTTPS, EMPTY);
    }

    record ClaimPair(String expectedClaim, String claim) {
    }
}
