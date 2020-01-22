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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.request.OpenIdAuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.response.*;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectHandler;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The default implementation of {@link OpenIdClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class DefaultOpenIdClient implements OpenIdClient {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdClient.class);

    private final OauthClientConfiguration clientConfiguration;
    private final OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher;
    private OpenIdProviderMetadata openIdProviderMetadata;
    private final OpenIdUserDetailsMapper userDetailsMapper;
    private final AuthorizationRedirectHandler redirectUrlBuilder;
    private final OpenIdAuthorizationResponseHandler authorizationResponseHandler;
    private SecureEndpoint tokenEndpoint;
    private final BeanContext beanContext;
    private final EndSessionEndpoint endSessionEndpoint;

    /**
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadataFetcher The provider metadata fetcher
     * @param userDetailsMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param beanContext The bean context
     * @param endSessionEndpoint The end session request
     */
    public DefaultOpenIdClient(OauthClientConfiguration clientConfiguration,
                               OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher,
                               @Nullable OpenIdUserDetailsMapper userDetailsMapper,
                               AuthorizationRedirectHandler redirectUrlBuilder,
                               OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                               BeanContext beanContext,
                               @Nullable EndSessionEndpoint endSessionEndpoint) {
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadataFetcher = openIdProviderMetadataFetcher;
        this.userDetailsMapper = userDetailsMapper;
        this.redirectUrlBuilder = redirectUrlBuilder;
        this.authorizationResponseHandler = authorizationResponseHandler;
        this.beanContext = beanContext;
        this.endSessionEndpoint = endSessionEndpoint;
    }

    @Override
    public String getName() {
        return clientConfiguration.getName();
    }

    @Override
    public boolean supportsEndSession() {
        return endSessionEndpoint != null;
    }

    @Override
    public Optional<HttpResponse> endSessionRedirect(HttpRequest request, Authentication authentication) {

        if (LOG.isTraceEnabled()) {
            LOG.trace("Starting end session flow to provider [{}]", getName());
        }
        return Optional.ofNullable(endSessionEndpoint)
                .map(esr -> esr.getUrl(request, authentication, getOpenIdProviderMetadata()))
                .map(url -> HttpResponse.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, url));
    }



    @Override
    public Publisher<HttpResponse> authorizationRedirect(HttpRequest originating) {
        AuthorizationRequest authorizationRequest = beanContext.createBean(OpenIdAuthorizationRequest.class, originating, clientConfiguration);
        String endpoint = getOpenIdProviderMetadata().getAuthorizationEndpoint();

        if (LOG.isTraceEnabled()) {
            LOG.trace("Starting authorization code grant flow to provider [{}]. Redirecting to [{}]", getName(), endpoint);
        }
        return Flowable.just(redirectUrlBuilder.redirect(authorizationRequest, endpoint));
    }

    @Override
    public Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request) {
        ConvertibleMultiValues<String> responseData = request.getBody()
                .map(body -> {
                    MutableConvertibleMultiValuesMap<String> map = new MutableConvertibleMultiValuesMap<>();
                    body.forEach((key, value) -> map.add(key, value.toString()));
                    return (ConvertibleMultiValues<String>) map;
                }).orElseGet(request::getParameters);

        if (isErrorCallback(responseData)) {
            AuthorizationErrorResponse errorResponse = beanContext.createBean(AuthorizationErrorResponse.class, request);
            if (LOG.isTraceEnabled()) {
                LOG.trace("Received an authorization error response from provider [{}]. Error: [{}]", getName(), errorResponse.getError());
            }
            throw new AuthorizationErrorResponseException(errorResponse);
        } else {
            OpenIdAuthorizationResponse authorizationResponse = beanContext.createBean(OpenIdAuthorizationResponse.class, request);
            if (LOG.isTraceEnabled()) {
                LOG.trace("Received a successful authorization response from provider [{}]", getName());
            }
            return authorizationResponseHandler.handle(authorizationResponse,
                    clientConfiguration,
                    getOpenIdProviderMetadata(),
                    userDetailsMapper,
                    getTokenEndpoint());
        }
    }

    /**
     * @param responseData The response data
     * @return True if the response indicates an error occurred.
     */
    protected boolean isErrorCallback(ConvertibleMultiValues<String> responseData) {
        return responseData.contains("error");
    }

    /**
     * @return The token endpoint
     */
    protected SecureEndpoint getTokenEndpoint() {
        if (tokenEndpoint == null) {
            List<String> authMethodsSupported = getOpenIdProviderMetadata().getTokenEndpointAuthMethodsSupported();
            List<AuthenticationMethod> authenticationMethods = null;
            if (authMethodsSupported != null) {
                authenticationMethods = authMethodsSupported.stream()
                        .map(String::toUpperCase)
                        .map(AuthenticationMethod::valueOf)
                        .collect(Collectors.toList());
            }
            tokenEndpoint = new DefaultSecureEndpoint(getOpenIdProviderMetadata().getTokenEndpoint(), authenticationMethods);
        }
        return tokenEndpoint;
    }

    public OpenIdProviderMetadata getOpenIdProviderMetadata() {
        if (openIdProviderMetadata == null) {
            Optional<OpenIdProviderMetadata> openIdProviderMetadataOpt = openIdProviderMetadataFetcher.fetchOpenIdProviderMetadataByQualifier(Qualifiers.byName(clientConfiguration.getName()));
            if (!openIdProviderMetadataOpt.isPresent()) {
                throw new ConfigurationException("open id provider metadata for " + clientConfiguration.getName() + " could not be fetched");
            }
            this.openIdProviderMetadata = openIdProviderMetadataOpt.get();
        }
        return openIdProviderMetadata;
    }
}
