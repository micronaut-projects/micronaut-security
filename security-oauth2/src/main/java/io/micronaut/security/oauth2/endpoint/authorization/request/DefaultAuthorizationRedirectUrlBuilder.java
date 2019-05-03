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

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.uri.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Builds an authorization redirect url.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultAuthorizationRedirectUrlBuilder implements AuthorizationRedirectUrlBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAuthorizationRedirectUrlBuilder.class);

    /**
     *
     * @param authorizationRequest The authorization request
     * @param authorizationEndpoint The authorization endpoint
     * @return Authorization redirect url
     */
    @Override
    public String buildUrl(AuthorizationRequest authorizationRequest,
                           String authorizationEndpoint) {
        Map<String, Object> arguments = instantiateParameters(authorizationRequest);
        String expandedUri = expandedUri(authorizationEndpoint, arguments);
        if (LOG.isDebugEnabled()) {
            LOG.debug("authorization redirect url {}", expandedUri);
        }
        return expandedUri;
    }

    /**
     * @param baseUrl Base Url
     * @param queryParams Query Parameters
     * @return The Expanded URI
     */
    protected String expandedUri(@Nonnull String baseUrl,
                                 @Nonnull Map<String, Object> queryParams) {
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
     *
     * @param authorizationRequest Authentication Request
     * @return A parameter map which contains the URL variables used to construct the authorization redirect url.
     */
    protected Map<String, Object> instantiateParameters(AuthorizationRequest authorizationRequest) {
        Map<String, Object> parameters = new HashMap<>();
        populateScope(authorizationRequest, parameters);
        populateResponseType(authorizationRequest, parameters);
        populateClientId(authorizationRequest, parameters);
        populateRedirectUri(authorizationRequest, parameters);
        populateState(authorizationRequest, parameters);
        if (authorizationRequest instanceof OpenIdAuthorizationRequest) {
            OpenIdAuthorizationRequest openIdAuthorizationRequest = (OpenIdAuthorizationRequest) authorizationRequest;
            populateResponseMode(openIdAuthorizationRequest, parameters);
            populateNonce(openIdAuthorizationRequest, parameters);
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
    protected void populateScope(@Nonnull AuthorizationRequest authorizationRequest,
                                 @Nonnull Map<String, Object> parameters) {
        Optional<String> optionalStr = authorizationRequest.getScopes().stream().reduce((a, b) -> a + StringUtils.SPACE + b);
        parameters.put(AuthorizationRequest.PARAMETER_SCOPE, optionalStr.orElse(OpenIdScope.OPENID.toString()));
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateResponseType(@Nonnull AuthorizationRequest authorizationRequest,
                                        @Nonnull Map<String, Object> parameters) {
        parameters.put(AuthorizationRequest.PARAMETER_RESPONSE_TYPE, authorizationRequest.getResponseType());
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateClientId(@Nonnull AuthorizationRequest authorizationRequest,
                                    @Nonnull Map<String, Object> parameters) {
        parameters.put(AuthorizationRequest.PARAMETER_CLIENT_ID, authorizationRequest.getClientId());
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateRedirectUri(@Nonnull AuthorizationRequest authorizationRequest,
                                       @Nonnull Map<String, Object> parameters) {
        parameters.put(AuthorizationRequest.PARAMETER_REDIRECT_URI, authorizationRequest.getRedirectUri() != null ? authorizationRequest.getRedirectUri() : authorizationRequest.getRedirectUri());
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateState(@Nonnull AuthorizationRequest authorizationRequest,
                                 @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getState() != null) {
            parameters.put(AuthorizationRequest.PARAMETER_STATE, authorizationRequest.getState());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateResponseMode(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                        @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getResponseMode() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_RESPONSE_MODE, authorizationRequest.getResponseMode());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateNonce(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                 @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getNonce() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_NONCE, authorizationRequest.getNonce());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateDisplay(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                   @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getDisplay() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_DISPLAY, authorizationRequest.getDisplay());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populatePrompt(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                  @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getPrompt() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_PROMPT, authorizationRequest.getPrompt().getPrompt());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateMaxAge(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                  @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getMaxAge() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_MAX_AGE, authorizationRequest.getMaxAge());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateUiLocales(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                     @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getUiLocales() != null) {
            Optional<String> optionalUiLocales = authorizationRequest.getUiLocales().stream().reduce((a, b) -> a + StringUtils.SPACE + b);
            optionalUiLocales.ifPresent(uiLocales -> parameters.put(OpenIdAuthorizationRequest.PARAMETER_UI_LOCALES, uiLocales));
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateIdTokenHint(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                       @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getIdTokenHint() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_ID_TOKEN_HINT, authorizationRequest.getIdTokenHint());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateLoginHint(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                     @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getLoginHint() != null) {
            parameters.put(OpenIdAuthorizationRequest.PARAMETER_LOGIN_HINT, authorizationRequest.getLoginHint());
        }
    }

    /**
     *
     * @param authorizationRequest Authentication Request
     * @param parameters Authentication Request Parameters
     */
    protected void populateAcrValues(@Nonnull OpenIdAuthorizationRequest authorizationRequest,
                                     @Nonnull Map<String, Object> parameters) {
        if (authorizationRequest.getAcrValues() != null) {
            Optional<String> optionalAcrValues = authorizationRequest.getAcrValues().stream().reduce((a, b) -> a + StringUtils.SPACE + b);
            optionalAcrValues.ifPresent(acrValues -> parameters.put(OpenIdAuthorizationRequest.PARAMETER_ACR_VALUES, acrValues));
        }
    }
}
