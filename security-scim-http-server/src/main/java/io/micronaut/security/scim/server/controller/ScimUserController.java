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
import io.micronaut.core.async.annotation.SingleResult;
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
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.protocol.ScimSearchRequest;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import io.micronaut.security.scim.server.service.ScimUserService;
import jakarta.validation.Valid;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimUserService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
class ScimUserController {
    private final ScimResourceEndpoint<User> endpoint;

    ScimUserController(ScimUserService service, ScimRequestParser requestParser) {
        this.endpoint = new ScimResourceEndpoint<>(service, requestParser);
    }

    @Post("/Users{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> create(
        @Body @Valid User user,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.create(user, attributes, excludedAttributes, request);
    }

    @Get("/Users/{id}{?attributes,excludedAttributes}")
    @SingleResult
    Publisher<MutableHttpResponse<?>> get(
        String id,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.get(id, attributes, excludedAttributes, request);
    }

    @Get("/Users{?attributes,excludedAttributes,filter,sortBy,sortOrder,startIndex,count}")
    @SingleResult
    Publisher<MutableHttpResponse<?>> search(
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

    @Post("/Users/.search")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> search(@Body ScimSearchRequest search, HttpRequest<?> request) {
        return endpoint.search(search, request);
    }

    @Put("/Users/{id}{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> replace(
        String id,
        @Body @Valid User user,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.replace(id, user, attributes, excludedAttributes, request);
    }

    @Patch("/Users/{id}{?attributes,excludedAttributes}")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> patch(
        String id,
        @Body ScimPatchRequest patch,
        @Nullable @QueryValue String attributes,
        @Nullable @QueryValue String excludedAttributes,
        HttpRequest<?> request
    ) {
        return endpoint.patch(id, patch, attributes, excludedAttributes, request);
    }

    @Delete("/Users/{id}")
    @SingleResult
    Publisher<MutableHttpResponse<?>> delete(String id, HttpRequest<?> request) {
        return endpoint.delete(id, request);
    }
}
