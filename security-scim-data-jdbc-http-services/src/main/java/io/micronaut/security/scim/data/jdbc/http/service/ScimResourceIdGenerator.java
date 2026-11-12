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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.scim.data.entities.ScimResourceType;

/**
 * Generates service-provider identifiers for new SCIM resources.
 *
 * @since 5.4.0
 */
@FunctionalInterface
@Experimental
public interface ScimResourceIdGenerator {

    /**
     * @param resourceType The type of resource being created
     * @return A new, globally unique and non-reassignable SCIM identifier
     * @since 5.4.0
     */
    String generateId(ScimResourceType resourceType);
}
