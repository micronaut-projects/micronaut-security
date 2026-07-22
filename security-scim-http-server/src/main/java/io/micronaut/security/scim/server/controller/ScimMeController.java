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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Put;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.security.scim.server.service.ScimMeService;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.net.URI;

@Internal
@Requires(classes = Controller.class)
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = ScimMeService.class)
@Controller("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}")
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
final class ScimMeController {
    private final ScimMeService service;
    private final ScimRequestParser requestParser;

    ScimMeController(ScimMeService service, ScimRequestParser requestParser) {
        this.service = service;
        this.requestParser = requestParser;
    }

    @Get("/Me")
    @SingleResult
    Publisher<MutableHttpResponse<?>> get(HttpRequest<?> request) {
        return redirect(request);
    }

    @Post("/Me")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> post(HttpRequest<?> request) {
        return redirect(request);
    }

    @Put("/Me")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> put(HttpRequest<?> request) {
        return redirect(request);
    }

    @Patch("/Me")
    @Consumes({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @SingleResult
    Publisher<MutableHttpResponse<?>> patch(HttpRequest<?> request) {
        return redirect(request);
    }

    @Delete("/Me")
    @SingleResult
    Publisher<MutableHttpResponse<?>> delete(HttpRequest<?> request) {
        return redirect(request);
    }

    private Publisher<MutableHttpResponse<?>> redirect(HttpRequest<?> request) {
        ScimAttributeSelection selection = requestParser.selection(
            request.getParameters().get("attributes"), request.getParameters().get("excludedAttributes"));
        return Mono.from(service.resolve(requestParser.context(request, selection)))
            .switchIfEmpty(Mono.error(new ScimException(HttpStatus.NOT_FOUND,
                "No SCIM resource is associated with the authenticated subject")))
            .map(ScimMeController::permanentRedirect);
    }

    private static MutableHttpResponse<?> permanentRedirect(URI location) {
        return HttpResponse.status(HttpStatus.PERMANENT_REDIRECT)
            .header(HttpHeaders.LOCATION, location.toString());
    }
}
