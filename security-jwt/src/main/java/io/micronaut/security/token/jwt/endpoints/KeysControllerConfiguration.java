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
package io.micronaut.security.token.jwt.endpoints;

import io.micronaut.security.endpoints.ControllerConfiguration;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * Encapsulates the configuration of {@link KeysController}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface KeysControllerConfiguration extends ControllerConfiguration {

    /**
     * The value used for the {@code max-age} directive of the {@code Cache-Control} header of the JWKS response.
     * A {@code null}, zero or negative duration disables the header.
     *
     * @return the maximum time a JWKS response may be cached by relying parties.
     * @since 5.4.0
     */
    @Nullable
    default Duration getCacheMaxAge() {
        return KeysControllerConfigurationProperties.DEFAULT_CACHE_MAX_AGE;
    }
}
