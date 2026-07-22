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
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import org.reactivestreams.Publisher;

/**
 * Optional application contract for searches across every resource type at the SCIM service root.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimRootSearchService {
    /**
     * @param query Parsed search request
     * @param context Request context
     * @return A single result page
     * @since 5.4.0
     */
    Publisher<ScimPage<ScimResource>> search(ScimQuery query, ScimRequestContext context);
}
