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
package io.micronaut.security.csrf.repository;

import io.micronaut.core.annotation.Internal;

/**
 * Condition to enable {@link CookieCsrfTokenRepository} via {@code micronaut.security.csrf.repositories.cookie.enabled}.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public final class CookieCsrfTokenRepositoryEnabledCondition extends CsrfRepositoryEnabledCondition {
    /**
     * Repository name used in the configuration key.
     */
    public static final String REPOSITORY_NAME = "cookie";

    /**
     * Constructor.
     */
    public CookieCsrfTokenRepositoryEnabledCondition() {
        super(REPOSITORY_NAME);
    }
}
