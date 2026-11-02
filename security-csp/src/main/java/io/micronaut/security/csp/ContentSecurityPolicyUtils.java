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
package io.micronaut.security.csp;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.DirectiveConfiguration;

import java.util.List;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.BLOB;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.DATA;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.FILESYSTEM;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.HTTP;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.HTTPS;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.MEDIASTREAM;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SINGLE_QUOTE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.WS;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.WSS;

/**
 * Internal helpers for serializing CSP source expressions.
 *
 * <p>CSP keywords and nonce/hash expressions are quoted, whereas host and scheme sources are
 * not. Callers use this helper only for the former group.</p>
 */
@Internal
final class ContentSecurityPolicyUtils {
    private ContentSecurityPolicyUtils() {
    }

    /**
     * Surrounds a CSP keyword or nonce/hash expression with single quotes when necessary.
     *
     * @param value the expression to serialize
     * @return {@code value} unchanged when it is already single-quoted; otherwise, the quoted value
     */
    public static String wrapInSingleQuotes(String value) {
        if (isWrappedInSingleQuotes(value)) {
            return value;
        }
        return SINGLE_QUOTE + value + SINGLE_QUOTE;
    }

    /**
     * Adds enabled scheme source expressions without quoting them.
     *
     * @param configuration the directive configuration
     * @param values the destination source expression list
     */
    static void addSchemeSources(DirectiveConfiguration configuration, List<String> values) {
        if (configuration.isHttp()) {
            values.add(HTTP);
        }
        if (configuration.isHttps()) {
            values.add(HTTPS);
        }
        if (configuration.isData()) {
            values.add(DATA);
        }
        if (configuration.isBlob()) {
            values.add(BLOB);
        }
        if (configuration.isFilesystem()) {
            values.add(FILESYSTEM);
        }
        if (configuration.isMediastream()) {
            values.add(MEDIASTREAM);
        }
        if (configuration.isWs()) {
            values.add(WS);
        }
        if (configuration.isWss()) {
            values.add(WSS);
        }
    }

    /**
     * Tests whether an expression already carries the single quotes required by CSP syntax.
     *
     * @param value the expression to examine
     * @return whether the expression starts and ends with a single quote
     */
    private static boolean isWrappedInSingleQuotes(String value) {
        return value.startsWith(SINGLE_QUOTE) && value.endsWith(SINGLE_QUOTE);
    }
}
