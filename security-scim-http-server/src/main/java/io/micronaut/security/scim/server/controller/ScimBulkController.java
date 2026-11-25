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
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.protocol.ScimBulkRequest;
import io.micronaut.security.scim.server.protocol.ScimBulkResponse;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.service.ScimBulkService;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimBulkService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
final class ScimBulkController {
    private final ScimBulkService service;
    private final ScimRequestParser requestParser;

    ScimBulkController(ScimBulkService service, ScimRequestParser requestParser) {
        this.service = service;
        this.requestParser = requestParser;
    }

    @Post("/Bulk")
    @ExecuteOn(TaskExecutors.BLOCKING)
    MutableHttpResponse<ScimBulkResponse> bulk(@Body ScimBulkRequest bulk, HttpRequest<?> request) {
        requestParser.validate(bulk);
        ScimBulkResponse response = service.execute(
            bulk, requestParser.context(request, ScimAttributeSelection.ALL));
        if (response == null) {
            throw new ScimException(HttpStatus.INTERNAL_SERVER_ERROR,
                "The application SCIM bulk service returned no response");
        }
        return HttpResponse.ok(response).contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE);
    }
}
