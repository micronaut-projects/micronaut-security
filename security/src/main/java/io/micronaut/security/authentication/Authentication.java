/*
 * Copyright 2017-2020 original authors
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

import javax.annotation.Nonnull;
import java.io.Serializable;
import java.security.Principal;
import java.util.Map;

/**
 * Represents the state of an authentication.
 *
 * @author James Kleeh
 * @since 1.0
 */
public interface Authentication extends Principal, Serializable {

    /**
     * In order to correctly implement the {@link Serializable} specification, this map
     * should be {@link Map<String, Serializable>}, however that would place a burden on
     * those not requiring serialization, forcing their values to conform to that spec.
     *
     * This is left intentionally as Object in order to meet both use cases and those
     * requiring serialization must ensure all values in the map implement {@link Serializable}.
     *
     * @return Any additional attributes in the authentication
     */
    @Nonnull
    Map<String, Object> getAttributes();
}
