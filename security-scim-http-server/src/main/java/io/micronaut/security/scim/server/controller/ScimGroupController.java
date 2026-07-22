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
package io.micronaut.security.scim.server.controller;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.protocol.ScimSearchRequest;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import io.micronaut.security.scim.server.service.ScimGroupService;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import jakarta.validation.Valid;
import org.jspecify.annotations.Nullable;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimGroupService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
class ScimGroupController {
    private final ScimResourceEndpoint<Group> endpoint;

    ScimGroupController(ScimGroupService service, ScimRequestParser requestParser) {
        this.endpoint = new ScimResourceEndpoint<>(service, requestParser);
    }

    @Post("/Groups{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> create(
        @Body @Valid Group group,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.create(group, attributes, excludedAttributes, request);
    }

    @Get("/Groups/{id}{?attributes,excludedAttributes}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> get(
        String id,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.get(id, attributes, excludedAttributes, request);
    }

    @Get("/Groups{?attributes,excludedAttributes,filter,sortBy,sortOrder,startIndex,count}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> search(
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        @Nullable @QueryValue String filter,
        @Nullable @QueryValue String sortBy,
        @Nullable @QueryValue ScimSortOrder sortOrder,
        @Nullable @QueryValue Integer startIndex,
        @Nullable @QueryValue Integer count,
        HttpRequest<?> request
    ) {
        return endpoint.search(attributes, excludedAttributes, filter, sortBy, sortOrder, startIndex, count, request);
    }

    @Post("/Groups/.search")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> search(@Body ScimSearchRequest search, HttpRequest<?> request) {
        return endpoint.search(search, request);
    }

    @Put("/Groups/{id}{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> replace(
        String id,
        @Body @Valid Group group,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.replace(id, group, attributes, excludedAttributes, request);
    }

    @Patch("/Groups/{id}{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> patch(
        String id,
        @Body ScimPatchRequest patch,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.patch(id, patch, attributes, excludedAttributes, request);
    }

    @Delete("/Groups/{id}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> delete(String id, HttpRequest<?> request) {
        return endpoint.delete(id, request);
    }
}
