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

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimListResponse;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.protocol.ScimSearchRequest;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import io.micronaut.security.scim.server.service.ScimResourceService;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

@Internal
final class ScimResourceEndpoint<T extends ScimResource> {
    private final ScimResourceService<T> service;
    private final ScimRequestParser requestParser;

    ScimResourceEndpoint(ScimResourceService<T> service, ScimRequestParser requestParser) {
        this.service = service;
        this.requestParser = requestParser;
    }

    Publisher<MutableHttpResponse<?>> create(
        T resource,
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        HttpRequest<?> request
    ) {
        ScimAttributeSelection selection = requestParser.selection(attributes, excludedAttributes);
        return one(service.create(resource, requestParser.context(request, selection)), "create")
            .map(result -> resourceResponse(HttpResponse.created(result.resource(), result.location()), result));
    }

    Publisher<MutableHttpResponse<?>> get(
        String id,
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        HttpRequest<?> request
    ) {
        ScimAttributeSelection selection = requestParser.selection(attributes, excludedAttributes);
        return Mono.from(service.get(id, requestParser.context(request, selection)))
            .switchIfEmpty(Mono.error(notFound(id)))
            .map(result -> {
                if (matchesIfNoneMatch(request.getHeaders().get(HttpHeaders.IF_NONE_MATCH), result.version())) {
                    return HttpResponse.notModified();
                }
                return resourceResponse(HttpResponse.ok(result.resource()), result);
            });
    }

    Publisher<MutableHttpResponse<?>> search(
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        @Nullable String filter,
        @Nullable String sortBy,
        @Nullable ScimSortOrder sortOrder,
        @Nullable Integer startIndex,
        @Nullable Integer count,
        HttpRequest<?> request
    ) {
        ScimQuery query = requestParser.query(attributes, excludedAttributes, filter, sortBy, sortOrder,
            startIndex, count);
        return search(query, request);
    }

    Publisher<MutableHttpResponse<?>> search(ScimSearchRequest searchRequest, HttpRequest<?> request) {
        return search(requestParser.query(searchRequest), request);
    }

    Publisher<MutableHttpResponse<?>> replace(
        String id,
        T resource,
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        HttpRequest<?> request
    ) {
        ScimAttributeSelection selection = requestParser.selection(attributes, excludedAttributes);
        return Mono.from(service.replace(id, resource, requestParser.context(request, selection)))
            .switchIfEmpty(Mono.error(notFound(id)))
            .map(result -> resourceResponse(HttpResponse.ok(result.resource()), result));
    }

    Publisher<MutableHttpResponse<?>> patch(
        String id,
        ScimPatchRequest patch,
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        HttpRequest<?> request
    ) {
        requestParser.validate(patch);
        ScimAttributeSelection selection = requestParser.selection(attributes, excludedAttributes);
        return Mono.from(service.patch(id, patch, requestParser.context(request, selection)))
            .switchIfEmpty(Mono.error(notFound(id)))
            .map(result -> resourceResponse(HttpResponse.ok(result.resource()), result));
    }

    Publisher<MutableHttpResponse<?>> delete(String id, HttpRequest<?> request) {
        return Mono.from(service.delete(id, requestParser.context(request, ScimAttributeSelection.ALL)))
            .then(Mono.fromSupplier(HttpResponse::noContent));
    }

    private Publisher<MutableHttpResponse<?>> search(ScimQuery query, HttpRequest<?> request) {
        return one(service.search(query, requestParser.context(request, query.attributes())), "search")
            .map(page -> HttpResponse.ok(ScimListResponse.fromPage(page))
                .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE));
    }

    private static <R> Mono<R> one(Publisher<R> publisher, String operation) {
        return Mono.from(publisher)
            .switchIfEmpty(Mono.error(new ScimException(HttpStatus.INTERNAL_SERVER_ERROR,
                "The application SCIM " + operation + " service returned no result")));
    }

    private static MutableHttpResponse<?> resourceResponse(
        MutableHttpResponse<?> response,
        ScimResourceResponse<?> result
    ) {
        response.contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .header(HttpHeaders.LOCATION, result.location().toString());
        if (result.version() != null) {
            response.header(HttpHeaders.ETAG, result.version());
        }
        return response;
    }

    private static boolean matchesIfNoneMatch(@Nullable String ifNoneMatch, @Nullable String version) {
        if (ifNoneMatch == null || version == null) {
            return false;
        }
        String normalizedVersion = weakValue(version);
        for (String candidate : ifNoneMatch.split(",")) {
            String trimmed = candidate.trim();
            if (trimmed.equals("*") || weakValue(trimmed).equals(normalizedVersion)) {
                return true;
            }
        }
        return false;
    }

    private static String weakValue(String etag) {
        return etag.startsWith("W/") ? etag.substring(2) : etag;
    }

    private static ScimException notFound(String id) {
        return new ScimException(HttpStatus.NOT_FOUND, "No SCIM resource exists with id " + id);
    }
}
