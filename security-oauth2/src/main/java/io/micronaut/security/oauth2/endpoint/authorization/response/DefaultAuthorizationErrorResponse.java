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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.errors.ErrorCode;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;
import java.util.Map;

/**
 * Default implementation of {@link AuthorizationErrorResponse}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
public class DefaultAuthorizationErrorResponse extends StateAwareAuthorizationCallback implements AuthorizationErrorResponse {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultAuthorizationErrorResponse.class);

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
    public ErrorCode getError() {
        return getError(responseData);
    }

    @NonNull
    static ErrorCode getError(ConvertibleMultiValues<String> responseData) {
        String name = responseData.get(JSON_KEY_ERROR);
        if (name != null) {
            name = name.toUpperCase(Locale.ENGLISH);
        }
        try {
            if (name != null) {
                return AuthorizationErrorCode.valueOf(name);
            }
        } catch (IllegalArgumentException e) {
            LOG.trace("{} not found in enum AuthorizationErrorCode", name);
        }
        return new ErrorCode() {
            @Override
            public String getErrorCode() {
                return responseData.get(JSON_KEY_ERROR);
            }

            @Override
            public String getErrorCodeDescription() {
                return responseData.get(JSON_KEY_ERROR_DESCRIPTION);
            }
        };
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
