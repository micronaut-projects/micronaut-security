/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.introspection;

import org.reactivestreams.Publisher;

import javax.annotation.Nonnull;
import javax.validation.constraints.NotNull;

/**
 * Responsible for sending requests to the introspection endpoint.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface IntrospectionEndpointClient {

    /**
     * @param requestContext Introspection request context
     * @param request Introspection request
     * @return An IntrospectionResponse object
     */
    @Nonnull
    Publisher<IntrospectionResponse> sendRequest(@Nonnull @NotNull IntrospectionRequestContext requestContext, @Nonnull @NotNull IntrospectionRequest request);

}
