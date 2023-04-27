/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.OauthAuthorizationEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.PkceChallenge;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.PkceFactory;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateFactory;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * The default implementation of {@link OauthAuthorizationRequest}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Prototype
@Internal
class DefaultOauthAuthorizationRequest implements OauthAuthorizationRequest {

    private final HttpRequest<?> request;
    private final OauthClientConfiguration oauthClientConfiguration;
    private final OauthRouteUrlBuilder oauthRouteUrlBuilder;
    private final StateFactory stateFactory;
    private final PkceFactory pkceFactory;

    /**
     * @param request                  The callback request
     * @param oauthClientConfiguration The client configuration
     * @param oauthRouteUrlBuilder     The oauth route URL builder
     * @param stateFactory             The state factory
     * @param pkceFactory              The PKCE factory
     */
    DefaultOauthAuthorizationRequest(@Parameter HttpRequest<?> request,
                                     @Parameter OauthClientConfiguration oauthClientConfiguration,
                                     OauthRouteUrlBuilder oauthRouteUrlBuilder,
                                     @Nullable StateFactory stateFactory,
                                     @Nullable PkceFactory pkceFactory) {
        this.request = request;
        this.oauthClientConfiguration = oauthClientConfiguration;
        this.oauthRouteUrlBuilder = oauthRouteUrlBuilder;
        this.stateFactory = stateFactory;
        this.pkceFactory = pkceFactory;
    }

    @Override
    @NonNull
    public String getClientId() {
        return oauthClientConfiguration.getClientId();
    }

    @Override
    public Optional<String> getState(MutableHttpResponse response) {
        return Optional.ofNullable(stateFactory)
            .map(sf -> sf.buildState(request, response, this));
    }

    @Override
    @NonNull
    public Optional<PkceChallenge> getPkceChallenge(@NonNull MutableHttpResponse<?> response) {
        return oauthClientConfiguration.getAuthorization()
            .flatMap(OauthAuthorizationEndpointConfiguration::getCodeChallengeMethod)
            .flatMap(codeChallengeMethod -> (pkceFactory == null) ?
                Optional.empty() : pkceFactory.buildChallenge(request, response, Collections.singletonList(codeChallengeMethod)).map(PkceChallenge.class::cast));
    }

    @Override
    @NonNull
    public List<String> getScopes() {
        return oauthClientConfiguration.getScopes();
    }

    @NonNull
    @Override
    public String getResponseType() {
        return ResponseType.CODE.toString();
    }

    @Override
    public Optional<String> getRedirectUri() {
        return Optional.of(oauthRouteUrlBuilder.buildCallbackUrl(request, oauthClientConfiguration.getName()).toString());
    }
}
