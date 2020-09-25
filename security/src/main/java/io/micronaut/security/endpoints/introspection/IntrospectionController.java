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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.reactivex.Flowable;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>.
 * @author Sergio del Amo
 * @since 2.1.0
 */
@Controller("${" + IntrospectionConfigurationProperties.PREFIX + ".path:/token_info}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class IntrospectionController {
    private static final Logger LOG = LoggerFactory.getLogger(IntrospectionController.class);

    protected final IntrospectionEndpointAuthorizer authorizer;
    protected final IntrospectionProcessor processor;

    /**
     *
     * @param processor Introspection Processor
     * @param authorizer Introspection Authorizer
     */
    public IntrospectionController(IntrospectionProcessor processor,
                                   @Nullable IntrospectionEndpointAuthorizer authorizer) {
        this.authorizer = authorizer;
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
    public Single<MutableHttpResponse<?>> tokenInfo(@NonNull @Body @Valid @NotNull IntrospectionRequest introspectionRequest,
                                                    @NonNull HttpRequest<?> request) {
        return (authorizer == null ?
                Single.just(true) :
                Flowable.fromPublisher(authorizer.isAuthorized(introspectionRequest, request)).first(false)
        ).flatMap(authorized -> {
            if (authorized) {
                return Flowable.fromPublisher(processor.introspect(introspectionRequest, request))
                        .map(introspectionResponse -> HttpResponse.ok(introspectionResponseAsJsonString(introspectionResponse)))
                        .first(HttpResponse.ok(introspectionResponseAsJsonString(new IntrospectionResponse(false))));
            } else {
                return Single.just(HttpResponse.unauthorized());
            }
        });
    }

    /**
     * This is necessary due to https://github.com/micronaut-projects/micronaut-core/issues/4179
     */
    @NonNull
    private String introspectionResponseAsJsonString(@NonNull IntrospectionResponse introspectionResponse) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(introspectionResponse);
        } catch (JsonProcessingException e) {
            LOG.warn("{}", e.getMessage());
            return "{\"active:\" false}";
        }
    }
}
