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

package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpParameters;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Objects;

/**
 * Adapts from {@link HttpParameters} to {@link AuthorizationResponse}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
public class DefaultAuthorizationResponse extends StateAwareAuthorizationCallback implements AuthorizationResponse {

    private final ConvertibleMultiValues<String> responseData;
    private final HttpRequest<Map<String, Object>> request;

    /**
     * Constructs an adapter from {@link HttpParameters} to {@link AuthorizationErrorResponse}.
     * @param request Http Parameters
     * @param stateSerDes State Serdes
     */
    public DefaultAuthorizationResponse(@Parameter HttpRequest<Map<String, Object>> request,
                                        StateSerDes stateSerDes) {
        super(stateSerDes);
        this.responseData = request.getBody()
                .map(body -> {
                    MutableConvertibleMultiValuesMap<String> map = new MutableConvertibleMultiValuesMap<>();
                    body.forEach((key, value) -> map.add(key, value.toString()));
                    return (ConvertibleMultiValues<String>) map;
                }).orElseGet(request::getParameters);
        this.request = request;
    }

    @Override
    protected String getStateValue() {
        return responseData.get(AuthorizationResponse.KEY_STATE);
    }

    @Nonnull
    @Override
    public String getCode() {
        return Objects.requireNonNull(responseData.get(AuthorizationResponse.KEY_CODE));
    }

    @Nonnull
    @Override
    public HttpRequest getCallbackRequest() {
        return request;
    }
}
