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

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.NONE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_NONE;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.QUOTED_SELF;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SELF;

/**
 * A directive in a Content Security Policy.
 *
 * <p>Values are stored in their header representation. Use {@link #values()} to obtain the
 * individual whitespace-separated CSP tokens. This type does not validate directive names or
 * source expressions; validation remains the responsibility of the browser applying the policy.</p>
 *
 * @param name the directive name
 * @param value the directive value, or {@code null} for directives without a value
 * @since 5.4.0
 */
public record ContentSecurityPolicyDirective(String name, @Nullable String value) {

    @Override
    public String toString() {
        return StringUtils.isEmpty(value())
                    ? name()
                    : name() + " " + value();
    }

    /**
     * Returns the whitespace-separated values of this directive.
     *
     * @return an immutable list of source-expression tokens, or an empty list if this directive has no value
     * @since 5.4.0
     */
    public List<String> values() {
        return StringUtils.isEmpty(value()) ? List.of() : List.of(value().trim().split("\\s+"));
    }

    /**
     * @return whether this directive has exactly the {@code none} or {@code 'none'} value
     * @since 5.4.0
     */
    public boolean isNone() {
        if (StringUtils.isEmpty(value())) {
            return false;
        }
        return NONE.equals(value()) || QUOTED_NONE.equals(value);
    }

    /**
     * @return whether this directive has exactly the {@code self} or {@code 'self'} value
     * @since 5.4.0
     */
    public boolean isSelf() {
        if (StringUtils.isEmpty(value())) {
            return false;
        }
        return SELF.equals(value()) || QUOTED_SELF.equals(value);
    }
}
