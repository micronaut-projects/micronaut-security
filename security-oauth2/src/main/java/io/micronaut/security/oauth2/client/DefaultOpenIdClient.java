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
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.request.OpenIdAuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.response.*;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionRequest;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

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

    private final OauthClientConfiguration clientConfiguration;
    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final OpenIdUserDetailsMapper userDetailsMapper;
    private final AuthorizationRedirectUrlBuilder redirectUrlBuilder;
    private final OpenIdAuthorizationResponseHandler authorizationResponseHandler;
    private final SecureEndpoint tokenEndpoint;
    private final BeanContext beanContext;
    private final EndSessionRequest endSessionRequest;

    /**
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param userDetailsMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param beanContext The bean context
     * @param endSessionRequest The end session request
     */
    public DefaultOpenIdClient(OauthClientConfiguration clientConfiguration,
                               OpenIdProviderMetadata openIdProviderMetadata,
                               @Nullable OpenIdUserDetailsMapper userDetailsMapper,
                               AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                               OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                               BeanContext beanContext,
                               @Nullable EndSessionRequest endSessionRequest) {
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.userDetailsMapper = userDetailsMapper;
        this.redirectUrlBuilder = redirectUrlBuilder;
        this.authorizationResponseHandler = authorizationResponseHandler;
        this.beanContext = beanContext;
        this.endSessionRequest = endSessionRequest;
        this.tokenEndpoint = getTokenEndpoint();
    }

    @Override
    public String getName() {
        return clientConfiguration.getName();
    }

    @Override
    public boolean supportsEndSession() {
        return endSessionRequest != null;
    }

    @Override
    public Optional<HttpResponse> endSessionRedirect(HttpRequest request, Authentication authentication) {
        return Optional.ofNullable(endSessionRequest)
                .map(esr -> esr.getUrl(request, authentication))
                .map(url -> HttpResponse.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, url));
    }

    @Override
    public Publisher<HttpResponse> authorizationRedirect(HttpRequest originating) {
        AuthorizationRequest authorizationRequest = beanContext.createBean(OpenIdAuthorizationRequest.class, originating, clientConfiguration);
        String url = redirectUrlBuilder.buildUrl(authorizationRequest,
                openIdProviderMetadata.getAuthorizationEndpoint());
        return Flowable.just(
                HttpResponse.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, url));
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
            AuthorizationErrorResponse callback = beanContext.createBean(AuthorizationErrorResponse.class, request);
            throw new AuthorizationErrorResponseException(callback);
        } else {
            AuthorizationResponse authorizationResponse = beanContext.createBean(AuthorizationResponse.class, request);
            return authorizationResponseHandler.handle(authorizationResponse,
                    clientConfiguration,
                    openIdProviderMetadata,
                    userDetailsMapper,
                    tokenEndpoint);
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
        List<String> authMethodsSupported = openIdProviderMetadata.getTokenEndpointAuthMethodsSupported();
        List<AuthenticationMethod> authenticationMethods = null;
        if (authMethodsSupported != null) {
            authenticationMethods = authMethodsSupported.stream()
                    .map(String::toUpperCase)
                    .map(AuthenticationMethod::valueOf)
                    .collect(Collectors.toList());
        }
        return new DefaultSecureEndpoint(openIdProviderMetadata.getTokenEndpoint(), authenticationMethods);
    }
}
