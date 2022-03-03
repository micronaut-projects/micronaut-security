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
package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;

import io.micronaut.core.annotation.NonNull;
import java.util.Map;
import java.util.Objects;

/**
 * The default implementation of {@link AuthorizationResponse} for
 * OAuth 2.0 provider authorization responses.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
public class DefaultOauthAuthorizationResponse extends AbstractAuthorizationResponse implements OauthAuthorizationResponse {

    /**
     * @param request The request
     * @param stateSerDes State Serdes
     */
    public DefaultOauthAuthorizationResponse(@Parameter HttpRequest<Map<String, Object>> request,
                                             StateSerDes stateSerDes) {
        super(request, stateSerDes);
    }

    @Override
    protected String getStateValue() {
        return responseData.get(AuthorizationResponse.KEY_STATE);
    }

    @NonNull
    @Override
    public String getCode() {
        return Objects.requireNonNull(responseData.get(AuthorizationResponse.KEY_CODE));
    }

    @NonNull
    @Override
    public HttpRequest<?> getCallbackRequest() {
        return request;
    }
}
