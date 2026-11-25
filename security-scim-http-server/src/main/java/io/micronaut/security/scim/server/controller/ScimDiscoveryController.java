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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.security.scim.core.Meta;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimListResponse;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimMessageSchemas;
import io.micronaut.security.scim.server.service.ScimDiscoveryService;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import org.jspecify.annotations.Nullable;

import java.util.List;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimDiscoveryService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
final class ScimDiscoveryController {
    private final ScimDiscoveryService service;
    private final ScimRequestParser requestParser;

    ScimDiscoveryController(ScimDiscoveryService service, ScimRequestParser requestParser) {
        this.service = service;
        this.requestParser = requestParser;
    }

    @Get("/ServiceProviderConfig")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> serviceProviderConfiguration(HttpRequest<?> request) {
        ScimRequestContext context = requestParser.context(request, ScimAttributeSelection.ALL);
        var result = service.getServiceProviderConfiguration(context);
        if (result == null) {
            throw new ScimException(HttpStatus.INTERNAL_SERVER_ERROR,
                "The application SCIM discovery service returned no service-provider configuration");
        }
        return response(result.resource(), result.location().toString(), result.version());
    }

    @Get("/Schemas{?filter}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> schemas(@Nullable @QueryValue String filter, HttpRequest<?> request) {
        rejectDiscoveryFilter(filter);
        return list(service.getSchemas(requestParser.context(request, ScimAttributeSelection.ALL)));
    }

    @Get("/Schemas/{id}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> schema(String id, HttpRequest<?> request) {
        return item(service.getSchemas(requestParser.context(request, ScimAttributeSelection.ALL)), id, request);
    }

    @Get("/ResourceTypes{?filter}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> resourceTypes(@Nullable @QueryValue String filter, HttpRequest<?> request) {
        rejectDiscoveryFilter(filter);
        return list(service.getResourceTypes(requestParser.context(request, ScimAttributeSelection.ALL)));
    }

    @Get("/ResourceTypes/{id}")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> resourceType(String id, HttpRequest<?> request) {
        return item(service.getResourceTypes(requestParser.context(request, ScimAttributeSelection.ALL)), id, request);
    }

    private static <T extends ScimResource> MutableHttpResponse<?> list(List<T> resources) {
        return HttpResponse.ok(new ScimListResponse<>(List.of(ScimMessageSchemas.LIST_RESPONSE),
                resources.size(), resources, 1, resources.size()))
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE);
    }

    private static <T extends ScimResource> MutableHttpResponse<?> item(
        List<T> resources,
        String id,
        HttpRequest<?> request
    ) {
        T resource = resources.stream()
            .filter(candidate -> id.equals(candidate.getId()))
            .findFirst()
            .orElseThrow(() -> new ScimException(HttpStatus.NOT_FOUND,
                "No SCIM discovery resource exists with id " + id));
        Meta meta = resource.getMeta();
        String version = meta == null ? null : meta.version();
        return response(resource, request.getUri().toString(), version);
    }

    private static MutableHttpResponse<?> response(ScimResource resource, String location, @Nullable String version) {
        MutableHttpResponse<?> response = HttpResponse.ok(resource)
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .header(HttpHeaders.LOCATION, location);
        if (version != null) {
            response.header(HttpHeaders.ETAG, version);
        }
        return response;
    }

    private static void rejectDiscoveryFilter(@Nullable String filter) {
        if (filter != null) {
            throw new ScimException(HttpStatus.FORBIDDEN, ScimErrorType.INVALID_FILTER,
                "Filtering is not supported for SCIM discovery endpoints");
        }
    }
}
