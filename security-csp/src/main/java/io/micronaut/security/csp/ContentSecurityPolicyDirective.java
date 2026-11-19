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

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_NONE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_SELF;

/**
 * A directive in a Content Security Policy.
 *
 * <p>Values are stored in their header representation. Use {@link #values()} to obtain the
 * individual whitespace-separated CSP tokens. This type does not validate directive names or
 * source expressions; validation remains the responsibility of the browser applying the policy.</p>
 *
 * @param name the directive name
 * @param value the directive value, or {@code null} for directives without a value
 * @since 5.6.0
 */
public record ContentSecurityPolicyDirective(String name, @Nullable String value) {

    @Override
    public String toString() {
        return StringUtils.hasText(value())
                    ? name() + " " + value().trim()
                    : name();
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
