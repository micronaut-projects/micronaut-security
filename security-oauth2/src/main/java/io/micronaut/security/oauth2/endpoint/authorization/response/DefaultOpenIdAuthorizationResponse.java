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
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;
import io.micronaut.security.oauth2.endpoint.nonce.validation.persistence.NoncePersistence;

import javax.annotation.Nullable;
import java.util.Map;
import java.util.Optional;

/**
 * @author James Kleeh
 * @since 1.2.0
 */
@Prototype
public class DefaultOpenIdAuthorizationResponse extends DefaultAuthorizationResponse implements OpenIdAuthorizationResponse {

    private final NoncePersistence noncePersistence;

    /**
     * @param request     The request
     * @param stateSerDes The state serializer/deserializer
     * @param noncePersistence The nonce persistence mechanism
     */
    public DefaultOpenIdAuthorizationResponse(@Parameter HttpRequest<Map<String, Object>> request,
                                              StateSerDes stateSerDes,
                                              @Nullable NoncePersistence noncePersistence) {
        super(request, stateSerDes);
        this.noncePersistence = noncePersistence;
    }

    @Nullable
    @Override
    public String getNonce() {
        return Optional.ofNullable(noncePersistence)
                .flatMap(np -> np.retrieveNonce(getCallbackRequest()))
                .orElse(null);
    }
}
