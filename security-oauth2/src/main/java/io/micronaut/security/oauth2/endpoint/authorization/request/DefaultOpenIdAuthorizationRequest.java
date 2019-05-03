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

import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.security.oauth2.url.CallbackUrlBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Provides an {@link AuthorizationRequest} by combining {@link OauthClientConfiguration},
 * {@link StateFactory}, {@link NonceProvider}.
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
public class DefaultOpenIdAuthorizationRequest implements OpenIdAuthorizationRequest {

    private final HttpRequest<?> request;
    private OauthClientConfiguration oauthConfiguration;
    private final CallbackUrlBuilder callbackUrlBuilder;
    private NonceProvider nonceProvider;
    private LoginHintResolver loginHintResolver;
    private IdTokenHintResolver idTokenHintResolver;
    private AuthorizationEndpointConfiguration endpointConfiguration;
    private final Supplier<String> stateSupplier;

    /**
     *
     * @param request The original request prior redirect.
     * @param oauthConfiguration The OAuth 2.0 configuration
     * @param callbackUrlBuilder The callback URL builder
     * @param stateFactory The state provider
     * @param nonceProvider The nonce provider
     * @param loginHintResolver The login hint provider
     * @param idTokenHintResolver The id token hint provider
     */
    public DefaultOpenIdAuthorizationRequest(@Parameter HttpRequest<?> request,
                                             @Parameter OauthClientConfiguration oauthConfiguration,
                                             CallbackUrlBuilder callbackUrlBuilder,
                                             @Nullable StateFactory stateFactory,
                                             @Nullable NonceProvider nonceProvider,
                                             @Nullable LoginHintResolver loginHintResolver,
                                             @Nullable IdTokenHintResolver idTokenHintResolver) {
        this.request = request;
        this.oauthConfiguration = oauthConfiguration;
        this.endpointConfiguration = oauthConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getAuthorization).orElse(null);
        this.callbackUrlBuilder = callbackUrlBuilder;
        this.nonceProvider = nonceProvider;
        this.loginHintResolver = loginHintResolver;
        this.idTokenHintResolver = idTokenHintResolver;
        this.stateSupplier = SupplierUtil.memoized(() -> {
            if (stateFactory != null) {
                return stateFactory.buildState(request);
            } else {
                return null;
            }
        });

    }

    @Override
    @Nonnull
    public String getClientId() {
        return oauthConfiguration.getClientId();
    }

    @Override
    @Nullable
    public String getState() {
        return stateSupplier.get();
    }

    @Nullable
    @Override
    public String getNonce() {
        return valueOrNull(nonceProvider, NonceProvider::generateNonce);
    }

    @Override
    @Nonnull
    public List<String> getScopes() {
        return oauthConfiguration.getScopes();
    }

    @Nonnull
    @Override
    public String getResponseType() {
        if (endpointConfiguration != null) {
            return endpointConfiguration.getResponseType().toString();
        }
        return ResponseType.CODE.toString();
    }

    @Nullable
    @Override
    public String getRedirectUri() {
        return callbackUrlBuilder.build(request, oauthConfiguration.getName());
    }

    @Nullable
    @Override
    public String getResponseMode() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getResponseMode);
    }

    @Nullable
    @Override
    public Display getDisplay() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getDisplay);
    }

    @Nullable
    @Override
    public Prompt getPrompt() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getPrompt);
    }

    @Nullable
    @Override
    public Integer getMaxAge() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getMaxAge);
    }

    @Nullable
    @Override
    public List<String> getUiLocales() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getUiLocales);
    }

    @Nullable
    @Override
    public String getIdTokenHint() {
        return valueOrNull(idTokenHintResolver, (resolver) -> resolver.resolve(request));
    }

    @Nullable
    @Override
    public String getLoginHint() {
        return valueOrNull(loginHintResolver, (resolver) -> resolver.resolve(request));
    }

    @Nullable
    @Override
    public List<String> getAcrValues() {
        return optionalValueOrNull(endpointConfiguration, AuthorizationEndpointConfiguration::getAcrValues);
    }

    private <T, R> R optionalValueOrNull(T provider, Function<T, Optional<R>> function) {
        if (provider != null) {
            return function.apply(provider).orElse(null);
        }
        return null;
    }

    private <T, R> R valueOrNull(T provider, Function<T, R> function) {
        if (provider != null) {
            return function.apply(provider);
        }
        return null;
    }

}
