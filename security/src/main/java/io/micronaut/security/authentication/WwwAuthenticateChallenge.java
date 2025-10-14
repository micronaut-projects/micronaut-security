/*
 * Copyright 2017-2025 original authors
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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;

/**
 *
 * This is a helper class to create a challenge, the value of a WWW-Authenticate response header as described in WWW-Authenticate.
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9110#section-11.6.1">RFC 9110 WWW-Authenticate</a>
 * @param authScheme Authentication Schema
 * @param authParameters Authentication Parameters
 * @since 4.14.0
 */
public record WwwAuthenticateChallenge(
    @NonNull String authScheme,
    @NonNull Map<String, Object> authParameters) {
    private static final String SPACE = " ";
    private static final String EQUAL = "=";
    private static final String COMMA = ",";
    private static final String DOUBLE_QUOTE = "\"";

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(authScheme);
        if (CollectionUtils.isNotEmpty(authParameters)) {
            sb.append(SPACE);
            List<String> params = new ArrayList<>(authParameters.size());
            for (Map.Entry<String, Object> entry : authParameters.entrySet()) {
                Object v = entry.getValue();
                if (v instanceof String s) {
                    params.add(entry.getKey() + EQUAL + DOUBLE_QUOTE + escape(s) + DOUBLE_QUOTE);
                } else {
                    params.add(entry.getKey() + EQUAL + v);
                }
            }
            sb.append(String.join(COMMA + SPACE, params));
        }
        return sb.toString();
    }

    private static String escape(String v) {
        StringBuilder out = new StringBuilder(v.length() + 8);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\');
            }
            out.append(c);
        }
        return out.toString();
    }

    /**
     * Create a new builder.
     * @return Builder
     */
    @NonNull
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link WwwAuthenticateChallenge}.
     */
    public static final class Builder {
        private String authScheme;
        private LinkedHashMap<String, Object> authParameters;

        /**
         * Set the authentication scheme.
         * @param authScheme The scheme, e.g. Basic, Bearer
         * @return this builder
         */
        @NonNull
        public Builder authScheme(@NonNull String authScheme) {
            this.authScheme = authScheme;
            return this;
        }

        /**
         * Add or replace a parameter.
         * @param name Parameter name
         * @param value Parameter value
         * @return this builder
         */
        @NonNull
        public Builder param(@NonNull String name, @NonNull Object value) {
            if (this.authParameters == null) {
                this.authParameters = new LinkedHashMap<>();
            }
            this.authParameters.put(name, value);
            return this;
        }

        /**
         * Build the challenge instance.
         * @return A new {@link WwwAuthenticateChallenge}
         */
        @NonNull
        public WwwAuthenticateChallenge build() {
            return new WwwAuthenticateChallenge(authScheme, authParameters);
        }
    }
}
