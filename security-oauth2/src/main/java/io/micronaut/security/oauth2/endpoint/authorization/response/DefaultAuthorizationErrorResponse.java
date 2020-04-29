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
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Locale;
import java.util.Map;

/**
 * Default implementation of {@link AuthorizationErrorResponse}
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
public class DefaultAuthorizationErrorResponse extends StateAwareAuthorizationCallback implements AuthorizationErrorResponse {

    private final ConvertibleMultiValues<String> responseData;

    /**
     * @param request     The callback request
     * @param stateSerDes The state serializer/deserializer
     */
    public DefaultAuthorizationErrorResponse(@Parameter HttpRequest<Map<String, Object>> request,
                                             StateSerDes stateSerDes) {
        super(stateSerDes);
        this.responseData = request.getBody()
                .map(body -> {
                    MutableConvertibleMultiValuesMap<String> map = new MutableConvertibleMultiValuesMap<>();
                    body.forEach((key, value) -> map.add(key, value.toString()));
                    return (ConvertibleMultiValues<String>) map;
                }).orElseGet(request::getParameters);
    }

    @NonNull
    @Override
    public AuthorizationError getError() {
        String name = responseData.get(JSON_KEY_ERROR).toUpperCase(Locale.ENGLISH);
        return AuthorizationError.valueOf(name);
    }

    @Nullable
    @Override
    public String getErrorDescription() {
        return responseData.get(JSON_KEY_ERROR_DESCRIPTION);
    }

    @Nullable
    @Override
    public String getStateValue() {
        return responseData.get(JSON_KEY_STATE);
    }

    @Nullable
    @Override
    public String getErrorUri() {
        return responseData.get(JSON_KEY_ERROR_URI);
    }

}
