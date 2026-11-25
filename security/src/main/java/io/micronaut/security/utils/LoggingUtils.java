/*
 * Copyright 2017-2022 original authors
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
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Utility methods to avoid verbosity of logging statements. Mostly used to help reduce the Cognitive Complexity of
 * some methods.
 *
 * @author Álvaro Sánchez-Mariscal
 */
@Internal
public final class LoggingUtils {

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

    private LoggingUtils() {
    }

    /**
     * Logs a message at the DEBUG level (only if it's enabled) according to the specified format and arguments.
     *
     * @param logger the SLF4J logger
     * @param message   the format string
     * @param args      a list of arguments
     */
    public static void debug(final Logger logger, final String message, final Object... args) {
        if (logger.isDebugEnabled()) {
            logger.debug(message, args);
        }
    }

    /**
     * Replaces the characters that could start a new line in a log file with an underscore, so that a value supplied
     * by a client or by a remote system cannot forge log entries (CWE-117). The ISO control characters, which include
     * carriage return and line feed, and the Unicode line and paragraph separators are replaced.
     *
     * @param value the value to log
     * @return the value without control characters, or {@code null} if the value is {@code null}
     * @since 5.6.0
     */
    public static @Nullable String sanitize(@Nullable final String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            if (breaksLine(value.charAt(i))) {
                char[] chars = value.toCharArray();
                for (int j = i; j < chars.length; j++) {
                    if (breaksLine(chars[j])) {
                        chars[j] = '_';
                    }
                }
                return new String(chars);
            }
        }
        return value;
    }

    /**
     * Sanitizes each value with {@link #sanitize(String)}.
     *
     * @param values the values to log
     * @return the sanitized values, in the iteration order of the collection, or {@code null} if the collection is
     * {@code null}
     * @since 5.6.0
     */
    public static @Nullable List<@Nullable String> sanitizeAll(@Nullable final Collection<@Nullable String> values) {
        if (values == null) {
            return null;
        }
        return values.stream().map(LoggingUtils::sanitize).toList();
    }

    private static boolean breaksLine(char c) {
        return Character.isISOControl(c) || c == '\u2028' || c == '\u2029';
    }

    /**
     * Logs the attributes of an authentication. At TRACE the attribute values are logged with the token values redacted.
     * At DEBUG only the attribute keys are logged.
     *
     * @param logger the SLF4J logger
     * @param authentication the authentication
     * @since 5.4.0
     */
    public static void logAuthenticationAttributes(final Logger logger, @Nullable final Authentication authentication) {
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
