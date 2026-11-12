/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.config;

import io.micronaut.core.util.Toggleable;
import java.util.List;

/**
 * Defines security configuration properties.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public interface SecurityConfiguration extends Toggleable, AuthenticationModeConfiguration {

    /**
     * Each pattern is either an IP wildcard (hexadecimal digits, dots, colons and {@code *}, where dots and colons match
     * literally, a {@code *} inside the pattern matches within one address segment, a trailing {@code *} matches the
     * rest of the address and hexadecimal digits match regardless of case) or, if it contains any other character or
     * starts with a dot, a regular expression matched against the whole host address.
     *
     * @return a list of IP patterns. e.g. [127.0.0.1, 192.168.1.*]
     */
    List<String> getIpPatterns();

    /**
     * @return a list of {@link InterceptUrlMapPattern}
     */
    List<InterceptUrlMapPattern> getInterceptUrlMap();

    /**
     * @return The authentication strategy
     */
    default AuthenticationStrategy getAuthenticationProviderStrategy() {
        return AuthenticationStrategy.ANY;
    }

    /**
     * For cases where no security rule handles a request and it is determined
     * that the request does not match any routes on the server, whether the response
     * should be to reject the request or allow the not found response to be returned.
     *
     * @return True if the response should be rejected.
     */
    default boolean isRejectNotFound() {
        return true;
    }

    /**
     * @since 3.7.2
     * @return Whether the intercept URL patterns should be prepended with context path if defined.
     */
    boolean isInterceptUrlMapPrependPatternWithContextPath();
}
