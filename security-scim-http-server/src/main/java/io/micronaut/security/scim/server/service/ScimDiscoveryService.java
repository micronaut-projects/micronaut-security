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
import io.micronaut.security.scim.core.ResourceType;
import io.micronaut.security.scim.core.Schema;
import io.micronaut.security.scim.core.ServiceProviderConfig;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import org.reactivestreams.Publisher;

/**
 * Application contract for RFC 7644 discovery endpoints.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimDiscoveryService {
    /**
     * @param context Request context
     * @return The service-provider configuration; must emit exactly one result
     * @since 5.4.0
     */
    Publisher<ScimResourceResponse<ServiceProviderConfig>> getServiceProviderConfiguration(ScimRequestContext context);

    /**
     * @param context Request context
     * @return All supported schemas
     * @since 5.4.0
     */
    Publisher<Schema> getSchemas(ScimRequestContext context);

    /**
     * @param context Request context
     * @return All supported resource types
     * @since 5.4.0
     */
    Publisher<ResourceType> getResourceTypes(ScimRequestContext context);
}
