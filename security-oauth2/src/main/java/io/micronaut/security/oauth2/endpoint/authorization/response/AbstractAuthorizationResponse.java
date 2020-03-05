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
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Objects;

/**
 * A base class for authorization responses to extend from
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public abstract class AbstractAuthorizationResponse extends StateAwareAuthorizationCallback implements AuthorizationResponse {

    protected final ConvertibleMultiValues<String> responseData;
    protected final HttpRequest<Map<String, Object>> request;

    /**
     * @param request The request
     * @param stateSerDes State Serdes
     */
    public AbstractAuthorizationResponse(@Parameter HttpRequest<Map<String, Object>> request,
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
    public HttpRequest<?> getCallbackRequest() {
        return request;
    }
}
