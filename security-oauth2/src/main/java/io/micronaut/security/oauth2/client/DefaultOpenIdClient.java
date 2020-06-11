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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.*;
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
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
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
    private final Supplier<OpenIdProviderMetadata> openIdProviderMetadata;
    private final OpenIdAuthenticationMapper openIdAuthenticationMapper;
    private final AuthorizationRedirectHandler redirectUrlBuilder;
    private final OpenIdAuthorizationResponseHandler authorizationResponseHandler;
    private final Supplier<SecureEndpoint> tokenEndpoint;
    private final BeanContext beanContext;
    private final EndSessionEndpoint endSessionEndpoint;

    /**
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param openIdAuthenticationMapper The user details mapper
     * @param redirectUrlBuilder The redirect URL builder
     * @param authorizationResponseHandler The authorization response handler
     * @param beanContext The bean context
     * @param endSessionEndpoint The end session request
     */
    public DefaultOpenIdClient(OauthClientConfiguration clientConfiguration,
                               Supplier<OpenIdProviderMetadata> openIdProviderMetadata,
                               @Nullable OpenIdAuthenticationMapper openIdAuthenticationMapper,
                               AuthorizationRedirectHandler redirectUrlBuilder,
                               OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                               BeanContext beanContext,
                               @Nullable EndSessionEndpoint endSessionEndpoint) {
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.openIdAuthenticationMapper = openIdAuthenticationMapper;
        this.redirectUrlBuilder = redirectUrlBuilder;
        this.authorizationResponseHandler = authorizationResponseHandler;
        this.beanContext = beanContext;
        this.endSessionEndpoint = endSessionEndpoint;
        this.tokenEndpoint = SupplierUtil.memoized(this::getTokenEndpoint);
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
    public Optional<MutableHttpResponse<?>> endSessionRedirect(HttpRequest<?> request, Authentication authentication) {

        if (LOG.isTraceEnabled()) {
            LOG.trace("Starting end session flow to provider [{}]", getName());
        }
        return Optional.ofNullable(endSessionEndpoint)
                .map(esr -> esr.getUrl(request, authentication))
                .map(url -> HttpResponse.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, url));
    }

    @Override
    public Publisher<MutableHttpResponse<?>> authorizationRedirect(HttpRequest<?> originating) {
        AuthorizationRequest authorizationRequest = beanContext.createBean(OpenIdAuthorizationRequest.class, originating, clientConfiguration);
        String endpoint = openIdProviderMetadata.get().getAuthorizationEndpoint();

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
                    openIdProviderMetadata.get(),
                    openIdAuthenticationMapper,
                    tokenEndpoint.get());
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
        List<String> authMethodsSupported = openIdProviderMetadata.get().getTokenEndpointAuthMethodsSupported();
        List<AuthenticationMethod> authenticationMethods = null;
        if (authMethodsSupported != null) {
            authenticationMethods = authMethodsSupported.stream()
                    .map(String::toUpperCase)
                    .map(AuthenticationMethod::valueOf)
                    .collect(Collectors.toList());
        }
        return new DefaultSecureEndpoint(openIdProviderMetadata.get().getTokenEndpoint(), authenticationMethods);
    }
}
