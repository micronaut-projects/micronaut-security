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

/**
 * A directive in a Content Security Policy.
 *
 * @param name the directive name
 * @param value the directive value, or {@code null} for directives without a value
 * @since 5.4.0
 */
public record CspDirective(String name, @Nullable String value) {

    @Override
    public String toString() {
        return StringUtils.isEmpty(value())
                    ? name()
                    : name() + " " + value();
    }
}
