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
package io.micronaut.security.csp.filters;

import io.micronaut.core.util.Toggleable;
import org.jspecify.annotations.Nullable;

/**
 * Configuration for the CSP server filter, which generates the request nonce, and for the response
 * header populator, which writes the CSP header. Both apply only to requests matching
 * {@link #getPattern()}; disabling the filter removes both.
 * @author Sergio del Amo
 * @since 5.6.0
 */
public interface ContentSecurityPolicyFilterConfiguration extends Toggleable {
    /**
     * Returns the URL pattern to which the CSP filter and response header apply.
     *
     * @return the ant-style request path pattern; defaults to {@code /**}
     */
    String getPattern();

    /**
     * Returns the {@code Cache-Control} value written to HTML responses of requests that received a
     * nonce, so that a shared cache does not replay one nonce to every visitor.
     *
     * @return the {@code Cache-Control} value, such as {@code private} or {@code no-store}, or
     * {@code null} or a blank value to leave the header to the application; defaults to {@code private}
     */
    @Nullable String getNonceCacheControl();
}
