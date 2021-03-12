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
package io.micronaut.security.oauth2.endpoint.authorization.request;

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.uri.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.core.annotation.NonNull;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Builds an authorization redirect url.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Singleton
public class DefaultAuthorizationRedirectHandler implements AuthorizationRedirectHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAuthorizationRedirectHandler.class);

    /**
     * @param authorizationRequest The authorization request
     * @param authorizationEndpoint The authorization endpoint
     * @return The authorization redirect url
     */
    @Override
    public MutableHttpResponse redirect(AuthorizationRequest authorizationRequest,
                                        String authorizationEndpoint) {
        MutableHttpResponse response = HttpResponse.status(HttpStatus.FOUND);
        Map<String, Object> arguments = instantiateParameters(authorizationRequest, response);
        String expandedUri = expandedUri(authorizationEndpoint, arguments);
        if (LOG.isTraceEnabled()) {
            LOG.trace("Built the authorization URL [{}]", expandedUri);
        }
        return response.header(HttpHeaders.LOCATION, expandedUri);
    }

    /**
     * @param baseUrl Base Url
     * @param queryParams Query Parameters
     * @return The Expanded URI
     */
    protected String expandedUri(@NonNull String baseUrl,
                                 @NonNull Map<String, Object> queryParams) {
        UriBuilder builder = UriBuilder.of(baseUrl);
        for (String k : queryParams.keySet()) {
            Object val = queryParams.get(k);
            if (val != null) {
                builder.queryParam(k, val);
            }
        }
        return builder.toString();
    }

    /**
     * @param authorizationRequest Authentication Request
     * @param response Authorization Redirect Response
     * @return A parameter map which contains the URL variables used to construct the authorization redirect url.
     */
    protected Map<String, Object> instantiateParameters(AuthorizationRequest authorizationRequest, MutableHttpResponse response) {
        Map<String, Object> parameters = new HashMap<>();
        populateScope(authorizationRequest, parameters);
        populateResponseType(authorizationRequest, parameters);
        populateClientId(authorizationRequest, parameters);
        populateRedirectUri(authorizationRequest, parameters);
        populateState(authorizationRequest, parameters, response);
        if (authorizationRequest instanceof OpenIdAuthorizationRequest) {
            OpenIdAuthorizationRequest openIdAuthorizationRequest = (OpenIdAuthorizationRequest) authorizationRequest;
            populateResponseMode(openIdAuthorizationRequest, parameters);
            populateNonce(openIdAuthorizationRequest, parameters, response);
            populateDisplay(openIdAuthorizationRequest, parameters);
            populatePrompt(openIdAuthorizationRequest, parameters);
            populateMaxAge(openIdAuthorizationRequest, parameters);
            populateUiLocales(openIdAuthorizationRequest, parameters);
            populateIdTokenHint(openIdAuthorizationRequest, parameters);
            populateLoginHint(openIdAuthorizationRequest, parameters);
            populateAcrValues(openIdAuthorizationRequest, parameters);
        }
        return parameters;
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateScope(@NonNull AuthorizationRequest authorizationRequest,
                                 @NonNull Map<String, Object> parameters) {
        Optional<String> optionalScope = authorizationRequest.getScopes().stream().reduce((a, b) -> a + StringUtils.SPACE + b);
        String defaultScope = authorizationRequest instanceof OpenIdAuthorizationRequest ? OpenIdScope.OPENID.toString() : null;
        String scope = optionalScope.orElse(defaultScope);
        if (scope != null) {
            parameters.put(AuthorizationRequest.PARAMETER_SCOPE, scope);
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateResponseType(@NonNull AuthorizationRequest authorizationRequest,
                                        @NonNull Map<String, Object> parameters) {
        parameters.put(AuthorizationRequest.PARAMETER_RESPONSE_TYPE, authorizationRequest.getResponseType());
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateClientId(@NonNull AuthorizationRequest authorizationRequest,
                                    @NonNull Map<String, Object> parameters) {
        parameters.put(AuthorizationRequest.PARAMETER_CLIENT_ID, authorizationRequest.getClientId());
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateRedirectUri(@NonNull AuthorizationRequest authorizationRequest,
                                       @NonNull Map<String, Object> parameters) {
        authorizationRequest.getRedirectUri().ifPresent(uri ->
                parameters.put(AuthorizationRequest.PARAMETER_REDIRECT_URI, uri));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     * @param response Authorization Redirect Response
     */
    protected void populateState(@NonNull AuthorizationRequest authorizationRequest,
                                 @NonNull Map<String, Object> parameters,
                                 @NonNull MutableHttpResponse response) {
        authorizationRequest.getState(response).ifPresent(state ->
                parameters.put(AuthorizationRequest.PARAMETER_STATE, state));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateResponseMode(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                        @NonNull Map<String, Object> parameters) {
        authorizationRequest.getResponseMode().ifPresent(rm ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_RESPONSE_MODE, rm));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     * @param response Authorization Redirect Response
     */
    protected void populateNonce(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                 @NonNull Map<String, Object> parameters,
                                 @NonNull MutableHttpResponse response) {
        authorizationRequest.getNonce(response).ifPresent(nonce ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_NONCE, nonce));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateDisplay(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                   @NonNull Map<String, Object> parameters) {
        authorizationRequest.getDisplay().ifPresent(display ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_DISPLAY, display));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populatePrompt(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                  @NonNull Map<String, Object> parameters) {
        authorizationRequest.getPrompt().ifPresent(prompt ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_PROMPT, prompt));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateMaxAge(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                  @NonNull Map<String, Object> parameters) {
        authorizationRequest.getMaxAge().ifPresent(maxAge ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_MAX_AGE, maxAge));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateUiLocales(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                     @NonNull Map<String, Object> parameters) {
        authorizationRequest.getUiLocales()
                .flatMap(uiLocales -> uiLocales.stream().reduce((a, b) -> a + StringUtils.SPACE + b))
                .ifPresent(uiLocales -> parameters.put(OpenIdAuthorizationRequest.PARAMETER_UI_LOCALES, uiLocales));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateIdTokenHint(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                       @NonNull Map<String, Object> parameters) {
        authorizationRequest.getIdTokenHint().ifPresent(idTokenHint ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_ID_TOKEN_HINT, idTokenHint));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateLoginHint(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                     @NonNull Map<String, Object> parameters) {
        authorizationRequest.getLoginHint().ifPresent(loginHint ->
                parameters.put(OpenIdAuthorizationRequest.PARAMETER_LOGIN_HINT, loginHint));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateAcrValues(@NonNull OpenIdAuthorizationRequest authorizationRequest,
                                     @NonNull Map<String, Object> parameters) {
        authorizationRequest.getAcrValues()
                .flatMap(acrValues -> acrValues.stream().reduce((a, b) -> a + StringUtils.SPACE + b))
                .ifPresent(acrValues -> parameters.put(OpenIdAuthorizationRequest.PARAMETER_ACR_VALUES, acrValues));
    }
}
