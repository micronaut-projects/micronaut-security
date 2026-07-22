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
package io.micronaut.security.scim.server.model;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.scim.core.ScimResource;
import org.jspecify.annotations.Nullable;

import java.net.URI;

/**
 * Application result containing a SCIM resource and its HTTP metadata.
 *
 * @param resource The persisted representation returned to the client
 * @param location The permanent resource location
 * @param version The ETag value, including quotes and an optional weakness prefix
 * @param <T> Resource type
 * @since 5.4.0
 */
@Experimental
public record ScimResourceResponse<T extends ScimResource>(
    T resource,
    URI location,
    @Nullable String version
) {
}
