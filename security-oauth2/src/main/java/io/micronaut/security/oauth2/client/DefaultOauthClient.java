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
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.request.OauthAuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.response.*;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The default implementation of {@link OauthClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class DefaultOauthClient implements OauthClient {

    private final OauthClientConfiguration clientConfiguration;
    private final OauthUserDetailsMapper userDetailsMapper;
    private final AuthorizationRedirectUrlBuilder redirectUrlBuilder;
    private final OauthAuthorizationResponseHandler authorizationResponseHandler;
    private final BeanContext beanContext;
    private final SecureEndpoint tokenEndpoint;

    /**
     * @param clientConfiguration The client configuration
     * @param userDetailsMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param beanContext The bean context
     */
    public DefaultOauthClient(OauthClientConfiguration clientConfiguration,
                              OauthUserDetailsMapper userDetailsMapper,
                              AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                              OauthAuthorizationResponseHandler authorizationResponseHandler,
                              BeanContext beanContext) {
        this.clientConfiguration = clientConfiguration;
        this.userDetailsMapper = userDetailsMapper;
        this.redirectUrlBuilder = redirectUrlBuilder;
        this.authorizationResponseHandler = authorizationResponseHandler;
        this.beanContext = beanContext;
        this.tokenEndpoint = getTokenEndpoint();
    }

    @Override
    public String getName() {
        return clientConfiguration.getName();
    }

    @Override
    public Publisher<HttpResponse> authorizationRedirect(HttpRequest originating) {
        AuthorizationRequest authorizationRequest = beanContext.createBean(OauthAuthorizationRequest.class, originating, clientConfiguration);
        String authorizationEndpoint = clientConfiguration.getAuthorization()
                .flatMap(EndpointConfiguration::getUrl)
                .orElseThrow(() -> new ConfigurationException("Oauth client requires the authorization URL to be set in configuration"));

        return Flowable.just(HttpResponse.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION,
                        redirectUrlBuilder.buildUrl(authorizationRequest, authorizationEndpoint)));
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
        String url = clientConfiguration.getToken()
                .flatMap(EndpointConfiguration::getUrl).orElseThrow(() -> new ConfigurationException("Oauth client requires the token endpoint URL to be set in configuration"));

        List<AuthenticationMethod> authenticationMethods = Collections.singletonList(
                clientConfiguration.getToken()
                        .flatMap(SecureEndpointConfiguration::getAuthMethod)
                        .orElse(AuthenticationMethod.CLIENT_SECRET_POST));

        return new DefaultSecureEndpoint(url, authenticationMethods);
    }
}
