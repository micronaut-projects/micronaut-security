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
package io.micronaut.security.csrf.session;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csrf.repository.CsrfRepositoryEnabledCondition;

/**
 * Condition to enable {@link SessionCsrfTokenRepository} via {@code micronaut.security.csrf.repositories.session.enabled}.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public final class SessionCsrfTokenRepositoryEnabledCondition extends CsrfRepositoryEnabledCondition {
    /**
     * Repository name used in the configuration key.
     */
    public static final String REPOSITORY_NAME = "session";

    /**
     * Constructor.
     */
    public SessionCsrfTokenRepositoryEnabledCondition() {
        super(REPOSITORY_NAME);
    }
}
