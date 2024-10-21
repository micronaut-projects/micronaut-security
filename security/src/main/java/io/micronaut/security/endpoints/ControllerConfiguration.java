/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.endpoints;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.MediaType;

import java.util.Set;

/**
 * Base configuration for all controllers.
 *
 * @author Álvaro Sánchez-Mariscal
 * @since 3.4.2
 */
@FunctionalInterface
public interface ControllerConfiguration extends Toggleable {

    /**
     * @return the path where the controller is enabled.
     */
    @NonNull
    String getPath();

    /**
     *
     * @return Supported HTTP methods for POST endpoints.
     * @since 4.11.0
     * @author Sergio del Amo
     */
    @NonNull
    default Set<MediaType> getPostContentTypes() {
        return Set.of(MediaType.APPLICATION_JSON_TYPE, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }
}
