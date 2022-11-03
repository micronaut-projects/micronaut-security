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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import org.reactivestreams.Publisher;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>.
 * @author Sergio del Amo
 * @since 2.1.0
 */
@Controller("${" + IntrospectionConfigurationProperties.PREFIX + ".path:/token_info}")
@Secured(SecurityRule.IS_AUTHENTICATED)
public class IntrospectionController {
    protected final IntrospectionProcessor processor;

    /**
     *
     * @param processor Introspection Processor
     * @since 3.3
     */
    public IntrospectionController(IntrospectionProcessor processor) {
        this.processor = processor;
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
    public Publisher<IntrospectionResponse> tokenInfo(@NonNull @Body @Valid @NotNull IntrospectionRequest introspectionRequest,
                                                      @NonNull HttpRequest<?> request) {
        return processor.introspect(introspectionRequest, request);
    }

    /**
     *
     * @param authentication Currently authenticated user
     * @param request HTTP Request
     * @return The HTTP Response containing an introspection response in the body
     */
    @Get
    @SingleResult
    public Publisher<IntrospectionResponse> echo(@NonNull Authentication authentication,
                                                 @NonNull HttpRequest<?> request) {
        return processor.introspect(authentication, request);
    }
}
