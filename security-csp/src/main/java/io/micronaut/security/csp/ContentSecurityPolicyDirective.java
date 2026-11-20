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

import io.micronaut.core.util.StringUtils;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.StringJoiner;
import java.util.regex.Pattern;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_NONE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_SELF;

/**
 * A directive in a Content Security Policy.
 *
 * <p>Values are stored in their header representation. Use {@link #values()} to obtain the
 * individual whitespace-separated CSP tokens. The name must be a directive name, and the value must
 * not contain a semicolon or a control character other than a tab, so that a directive cannot end
 * itself or the header and add directives. Otherwise, source expressions are written verbatim: a
 * value built from request or tenant data can still add source expressions with a space, or a
 * second policy with a comma, so validate such data before passing it.</p>
 *
 * @param name the directive name
 * @param value the directive value, or {@code null} for directives without a value
 * @since 5.6.0
 */
public record ContentSecurityPolicyDirective(String name, @Nullable String value) {
    private static final String QUOTED_NONCE_PREFIX = "'nonce-";
    private static final String REDACTED_NONCE = QUOTED_NONCE_PREFIX + "[redacted]'";
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9-]+");
    private static final Pattern UNSAFE_VALUE_CHARACTERS = Pattern.compile("[;\\x00-\\x08\\x0A-\\x1F\\x7F]");

    /**
     * Creates a directive.
     *
     * @param name the directive name, made of letters, digits and hyphens
     * @param value the directive value, or {@code null} for directives without a value
     * @throws IllegalArgumentException if the name is not a directive name, or the value contains a
     * semicolon or a control character other than a tab
     */
    public ContentSecurityPolicyDirective {
        if (!NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("A Content Security Policy directive name must consist of letters, digits and hyphens");
        }
        if (value != null && UNSAFE_VALUE_CHARACTERS.matcher(value).find()) {
            throw new IllegalArgumentException("The value of the Content Security Policy directive " + name
                + " must not contain a semicolon or a control character, which would end the directive or the header");
        }
    }

    /**
     * Serializes this directive as it appears in a CSP header value.
     *
     * @return the directive name followed by its trimmed value, if any
     * @since 5.6.0
     */
    public String toHeaderValue() {
        return StringUtils.hasText(value())
                    ? name() + " " + value().trim()
                    : name();
    }

    /**
     * Describes this directive for logs and debuggers. Nonce source expressions are redacted
     * because a nonce is a secret of the response that carries it; use {@link #toHeaderValue()} to
     * serialize the directive.
     *
     * @return the directive name followed by its values, with nonces redacted
     */
    @Override
    public String toString() {
        List<String> values = values();
        if (values.isEmpty()) {
            return name();
        }
        StringJoiner joiner = new StringJoiner(" ", name() + " ", "");
        for (String token : values) {
            joiner.add(token.regionMatches(true, 0, QUOTED_NONCE_PREFIX, 0, QUOTED_NONCE_PREFIX.length()) ? REDACTED_NONCE : token);
        }
        return joiner.toString();
    }

    /**
     * Returns the whitespace-separated values of this directive.
     *
     * @return an immutable list of source-expression tokens, or an empty list if this directive has no value
     * @since 5.6.0
     */
    public List<String> values() {
        return StringUtils.hasText(value()) ? List.of(value().trim().split("\\s+")) : List.of();
    }

    /**
     * Tests whether this directive disables its controlled resource or behavior.
     *
     * <p>Only the quoted keyword counts: an unquoted {@code none} is a host source named
     * {@code none}.</p>
     *
     * @return whether this directive has exactly the {@code 'none'} value
     * @since 5.6.0
     */
    public boolean isNone() {
        return value() != null && QUOTED_NONE.equals(value().trim());
    }

    /**
     * Tests whether this directive permits only the protected resource's origin.
     *
     * <p>Only the quoted keyword counts: an unquoted {@code self} is a host source named
     * {@code self}.</p>
     *
     * @return whether this directive has exactly the {@code 'self'} value
     * @since 5.6.0
     */
    public boolean isSelf() {
        return value() != null && QUOTED_SELF.equals(value().trim());
    }
}
