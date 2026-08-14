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
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.protocol.ScimListResponse;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.protocol.ScimSearchRequest;
import io.micronaut.security.scim.server.service.ScimRootSearchService;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimRootSearchService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
final class ScimRootSearchController {
    private final ScimRootSearchService service;
    private final ScimRequestParser requestParser;

    ScimRootSearchController(ScimRootSearchService service, ScimRequestParser requestParser) {
        this.service = service;
        this.requestParser = requestParser;
    }

    @Post("/.search")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<?> search(@Body ScimSearchRequest search, HttpRequest<?> request) {
        ScimQuery query = requestParser.query(search);
        var page = service.search(query, requestParser.context(request, query.attributes()));
        if (page == null) {
            throw new ScimException(HttpStatus.INTERNAL_SERVER_ERROR,
                "The application SCIM root search service returned no page");
        }
        return HttpResponse.ok(ScimListResponse.fromPage(page))
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE);
    }
}
