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
package io.micronaut.security.scim.server.service;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import org.reactivestreams.Publisher;

import java.net.URI;

/**
 * Optional application contract for the RFC 7644 {@code /Me} authenticated-subject alias.
 * The server responds with a 308 redirect to the permanent resource URI returned by the application.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimMeService {
    /**
     * Resolves the current authenticated subject to its permanent SCIM resource URI.
     *
     * @param context Request context
     * @return The permanent resource URI; must emit exactly one result
     * @since 5.4.0
     */
    Publisher<URI> resolve(ScimRequestContext context);
}
