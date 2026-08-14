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
package io.micronaut.security.scim.data.entities;

import io.micronaut.core.annotation.Experimental;

/**
 * Resource types supported by the RFC 7643 persistence entities.
 *
 * @since 5.4.0
 */
@Experimental
public enum ScimResourceType {
    /**
     * An RFC 7643 User resource.
     */
    USER,

    /**
     * An RFC 7643 Group resource.
     */
    GROUP
}
