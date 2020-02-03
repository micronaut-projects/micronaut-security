/*
 * Copyright 2017-2020 original authors
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
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.AuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.security.oauth2.endpoint.nonce.NonceFactory;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Optional;

/**
 * The default {@link OpenIdAuthorizationRequest} implementation.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Prototype
@Requires(configuration = "io.micronaut.security.token.jwt")
@Internal
class DefaultOpenIdAuthorizationRequest implements OpenIdAuthorizationRequest {

    private final HttpRequest<?> request;
    private OauthClientConfiguration oauthConfiguration;
    private final StateFactory stateFactory;
    private final NonceFactory nonceFactory;
    private LoginHintResolver loginHintResolver;
    private IdTokenHintResolver idTokenHintResolver;
    private AuthorizationEndpointConfiguration endpointConfiguration;
    private final OauthRouteUrlBuilder oauthRouteUrlBuilder;

    /**
     * @param request The original request prior redirect.
     * @param oauthConfiguration The OAuth 2.0 configuration
     * @param oauthRouteUrlBuilder The oauth route URL builder
     * @param stateFactory The state provider
     * @param nonceFactory The nonce provider
     * @param loginHintResolver The login hint provider
     * @param idTokenHintResolver The id token hint provider
     */
    public DefaultOpenIdAuthorizationRequest(@Parameter HttpRequest<?> request,
                                             @Parameter OauthClientConfiguration oauthConfiguration,
                                             OauthRouteUrlBuilder oauthRouteUrlBuilder,
                                             @Nullable StateFactory stateFactory,
                                             @Nullable NonceFactory nonceFactory,
                                             @Nullable LoginHintResolver loginHintResolver,
                                             @Nullable IdTokenHintResolver idTokenHintResolver) {
        this.request = request;
        this.oauthConfiguration = oauthConfiguration;
        this.endpointConfiguration = oauthConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getAuthorization).orElse(null);
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateFactory = stateFactory;
        this.nonceFactory = nonceFactory;
        this.loginHintResolver = loginHintResolver;
        this.idTokenHintResolver = idTokenHintResolver;
    }

    @Override
    @Nonnull
    public String getClientId() {
        return oauthConfiguration.getClientId();
    }

    @Override
    public Optional<String> getState(MutableHttpResponse response) {
        return Optional.ofNullable(stateFactory)
                .map(sf -> sf.buildState(request, response, this));
    }

    @Nullable
    @Override
    public Optional<String> getNonce(MutableHttpResponse response) {
        return Optional.ofNullable(nonceFactory)
                .map(nf -> nf.buildNonce(request, response));
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

    @Override
    public Optional<String> getRedirectUri() {
        return Optional.of(oauthRouteUrlBuilder.buildCallbackUrl(request, oauthConfiguration.getName()).toString());
    }

    @Override
    public Optional<String> getResponseMode() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getResponseMode);
    }

    @Override
    public Optional<Display> getDisplay() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getDisplay);
    }

    @Override
    public Optional<Prompt> getPrompt() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getPrompt);
    }

    @Override
    public Optional<Integer> getMaxAge() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getMaxAge);
    }

    @Override
    public Optional<List<String>> getUiLocales() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getUiLocales);
    }

    @Override
    public Optional<String> getIdTokenHint() {
        return Optional.ofNullable(idTokenHintResolver)
                .map(resolver -> resolver.resolve(request));
    }

    @Override
    public Optional<String> getLoginHint() {
        return Optional.ofNullable(loginHintResolver)
                .map(resolver -> resolver.resolve(request));
    }

    @Override
    public Optional<List<String>> getAcrValues() {
        return Optional.ofNullable(endpointConfiguration)
                .flatMap(AuthorizationEndpointConfiguration::getAcrValues);
    }

}
