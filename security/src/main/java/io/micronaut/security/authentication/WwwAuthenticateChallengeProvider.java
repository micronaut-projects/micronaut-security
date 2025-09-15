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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

/**
 * API to provide WWW-Authenticate Response Header Challenges.
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9110#section-11.6.1">RFC 9110 WWW-Authenticate</a>
 * @since 4.14.0
 */
@Experimental
@FunctionalInterface
public interface WwwAuthenticateChallengeProvider<T> {
    /**
     *
     * @param request The Request
     * @return The WWW-Authenticate response header challenge
     */
    @NonNull
    String getWwwAuthenticateChallenge(@Nullable T request);
}
