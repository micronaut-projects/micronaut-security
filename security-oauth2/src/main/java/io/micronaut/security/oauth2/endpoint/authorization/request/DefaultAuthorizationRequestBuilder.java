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

package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;

import javax.annotation.Nullable;
import javax.inject.Singleton;

/**
 * Default implementation of {@link AuthorizationRequestBuilder}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultAuthorizationRequestBuilder implements AuthorizationRequestBuilder {

    private final CallbackUrlBuilder callbackUrlBuilder;
    private final StateFactory stateFactory;
    private final NonceProvider nonceProvider;
    private final LoginHintResolver loginHintResolver;
    private final IdTokenHintResolver idTokenHintResolver;

    /**
     * @param stateFactory Authorization state provider
     * @param nonceProvider Authorization nonce provider
     * @param loginHintResolver Login Hint Provider
     * @param idTokenHintResolver Id Token Hint Provider
     */
    public DefaultAuthorizationRequestBuilder(CallbackUrlBuilder callbackUrlBuilder,
                                              @Nullable StateFactory stateFactory,
                                              @Nullable NonceProvider nonceProvider,
                                              @Nullable LoginHintResolver loginHintResolver,
                                              @Nullable IdTokenHintResolver idTokenHintResolver) {
        this.callbackUrlBuilder = callbackUrlBuilder;
        this.stateFactory = stateFactory;
        this.nonceProvider = nonceProvider;
        this.loginHintResolver = loginHintResolver;
        this.idTokenHintResolver = idTokenHintResolver;
    }

    @Override
    public AuthorizationRequest buildRequest(HttpRequest<?> request, OauthClientConfiguration oauthConfiguration) {
        return new DefaultOpenIdAuthorizationRequest(request,
                oauthConfiguration,
                callbackUrlBuilder,
                stateFactory,
                nonceProvider,
                loginHintResolver,
                idTokenHintResolver);
    }
}
