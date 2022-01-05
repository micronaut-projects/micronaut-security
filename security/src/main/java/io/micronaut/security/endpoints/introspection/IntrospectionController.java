/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.endpoints.introspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.jackson.databind.JacksonDatabindMapper;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>.
 * @author Sergio del Amo
 * @since 2.1.0
 */
@Controller("${" + IntrospectionConfigurationProperties.PREFIX + ".path:/token_info}")
@Secured(SecurityRule.IS_AUTHENTICATED)
public class IntrospectionController {
    private static final Logger LOG = LoggerFactory.getLogger(IntrospectionController.class);

    protected final IntrospectionProcessor processor;
    private final JsonMapper jsonMapper;

    /**
     *
     * @param processor Introspection Processor
     * @deprecated Use {@link #IntrospectionController(IntrospectionProcessor, JsonMapper)} instead
     */
    @Deprecated
    public IntrospectionController(IntrospectionProcessor processor) {
        this.processor = processor;
        this.jsonMapper = new JacksonDatabindMapper(new ObjectMapper());
    }

    /**
     *
     * @param processor Introspection Processor
     * @since 3.3
     */
    @Inject
    public IntrospectionController(IntrospectionProcessor processor, JsonMapper jsonMapper) {
        this.processor = processor;
        this.jsonMapper = jsonMapper;
    }

    /**
     *
     * @param introspectionRequest Introspection Request
     * @param request HTTP Request
     * @return The HTTP Response containing an introspection response in the body
     */
    @Post
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @SingleResult
    public Publisher<MutableHttpResponse<?>> tokenInfo(@NonNull @Body @Valid @NotNull IntrospectionRequest introspectionRequest,
                                                       @NonNull HttpRequest<?> request) {
        return Flux.from(processor.introspect(introspectionRequest, request))
                .map(this::introspectionResponseAsJsonString)
                .defaultIfEmpty(introspectionResponseAsJsonString(new IntrospectionResponse(false)))
                .map(HttpResponse::ok);
    }

    /**
     *
     * @param authentication Currently authenticated user
     * @param request HTTP Request
     * @return The HTTP Response containing an introspection response in the body
     */
    @Get
    @SingleResult
    public Publisher<MutableHttpResponse<?>> echo(@NonNull Authentication authentication,
                                               @NonNull HttpRequest<?> request) {
        return Flux.from(processor.introspect(authentication, request))
                .map(this::introspectionResponseAsJsonString)
                .defaultIfEmpty(introspectionResponseAsJsonString(new IntrospectionResponse(false)))
                .map(HttpResponse::ok);
    }

    /**
     * This is necessary due to https://github.com/micronaut-projects/micronaut-core/issues/4179 .
     */
    @NonNull
    private String introspectionResponseAsJsonString(@NonNull IntrospectionResponse introspectionResponse) {
        try {
            return new String(jsonMapper.writeValueAsBytes(introspectionResponse), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.warn("{}", e.getMessage());
            return "{\"active:\" false}";
        }
    }
}
