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
package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Utility methods for {@link Authentication}.
 *
 * @since 5.4.0
 */
@Internal
public final class AuthenticationUtils {

    private static final String REDACTED = "<redacted>";

    /**
     * Suffix (compared case-insensitively) of authentication attribute keys whose values must never be logged.
     */
    private static final String SENSITIVE_ATTRIBUTE_KEY_SUFFIX = "token";

    /**
     * Authentication attribute keys whose values must never be logged.
     * These mirror {@code OauthAuthenticationMapper.ACCESS_TOKEN_KEY}, {@code OauthAuthenticationMapper.REFRESH_TOKEN_KEY}
     * and {@code OpenIdAuthenticationMapper.OPENID_TOKEN_KEY} from the {@code micronaut-security-oauth2} module,
     * which this module cannot depend on.
     */
    private static final String[] SENSITIVE_ATTRIBUTE_KEYS = {"accessToken", "refreshToken", "openIdToken"};

    private AuthenticationUtils() {
    }

    /**
     * Logs the attributes of an authentication. At TRACE the attribute values are logged with the token values redacted.
     * At DEBUG only the attribute keys are logged.
     *
     * @param logger the SLF4J logger
     * @param authentication the authentication
     */
    public static void logAttributes(Logger logger, @Nullable Authentication authentication) {
        if (authentication == null) {
            return;
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Authentication attributes: {}", authentication.getAttributes()
                    .entrySet()
                    .stream()
                    .map(entry -> entry.getKey() + "=>" + redactedAttributeValue(entry.getKey(), entry.getValue()))
                    .collect(Collectors.joining(", ")));
        } else if (logger.isDebugEnabled()) {
            // Only the keys are logged at DEBUG. Attribute values may contain credentials (e.g. OAuth 2.0 access, refresh and ID tokens).
            logger.debug("Authentication attributes: {}", authentication.getAttributes().keySet());
        }
    }

    /**
     * Returns the string representation of an authentication attribute value suitable for logging.
     * Values whose key names a token are redacted so that credentials are never written to the logs.
     *
     * @param key the attribute key
     * @param value the attribute value
     * @return the value to log
     */
    private static String redactedAttributeValue(String key, @Nullable Object value) {
        if (value == null) {
            return "null";
        }
        return isSensitiveAttributeKey(key) ? REDACTED : value.toString();
    }

    private static boolean isSensitiveAttributeKey(String key) {
        if (key == null) {
            return false;
        }
        for (String sensitiveKey : SENSITIVE_ATTRIBUTE_KEYS) {
            if (sensitiveKey.equalsIgnoreCase(key)) {
                return true;
            }
        }
        return key.toLowerCase(Locale.ROOT).endsWith(SENSITIVE_ATTRIBUTE_KEY_SUFFIX);
    }
}
