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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.token.reader.TokenResolver;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides specific configuration to logout from Okta.
 *
 * <p>The {@code id_token_hint} parameter is populated with the ID token obtained during the authorization code flow when it is
 * available as the {@link OpenIdAuthenticationMapper#OPENID_TOKEN_KEY} authentication attribute. Otherwise, when
 * {@code micronaut.security.authentication} is {@code idtoken}, it is populated with the token which authenticated the current request,
 * as recorded in the {@link SecurityFilter#TOKEN} request attribute. Other tokens present in the request, for example an {@code Authorization} header added
 * by a gateway, are never forwarded to the OpenID provider.</p>
 *
 * @see <a href="https://developer.okta.com/docs/api/resources/oidc/#logout">Okta Logout Endpont</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public class OktaEndSessionEndpoint extends AbstractEndSessionRequest {

    private static final Logger LOG = LoggerFactory.getLogger(OktaEndSessionEndpoint.class);
    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";

    private final SecurityConfiguration securityConfiguration;

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     * @param securityConfiguration Security configuration
     * @since 3.11.3
     */
    public OktaEndSessionEndpoint(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                  OauthClientConfiguration clientConfiguration,
                                  Supplier<OpenIdProviderMetadata> providerMetadata,
                                  SecurityConfiguration securityConfiguration) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
        this.securityConfiguration = securityConfiguration;
    }

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration The client configuration
     * @param providerMetadata The provider metadata supplier
     * @param securityConfiguration Security configuration
     * @param tokenResolver Token Resolver. No longer used: only the token which authenticated the request is sent as {@code id_token_hint}
     * @deprecated Use {@link #OktaEndSessionEndpoint(EndSessionCallbackUrlBuilder, OauthClientConfiguration, Supplier, SecurityConfiguration)} instead.
     */
    @Deprecated
    public OktaEndSessionEndpoint(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                  OauthClientConfiguration clientConfiguration,
                                  Supplier<OpenIdProviderMetadata> providerMetadata,
                                  SecurityConfiguration securityConfiguration,
                                  TokenResolver tokenResolver) {
        this(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata, securityConfiguration);
    }

    @Override
    protected String getUrl() {
        return providerMetadataSupplier.get().getEndSessionEndpoint();
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest<?> originating,
                                               Authentication authentication) {
        Optional<String> idToken = parseIdToken(originating, authentication);
        Map<String, Object> arguments = new HashMap<>();
        idToken.ifPresent(token -> arguments.put(PARAM_ID_TOKEN_HINT, token));
        arguments.put(PARAM_POST_LOGOUT_REDIRECT_URI, getRedirectUri(originating));
        return arguments;
    }

    /**
     * Resolves the ID token to send as {@code id_token_hint}. The {@link OpenIdAuthenticationMapper#OPENID_TOKEN_KEY} authentication
     * attribute takes precedence. Otherwise, in {@link AuthenticationMode#IDTOKEN} mode, the token which authenticated the request is used.
     * Tokens found in the request which did not authenticate it are ignored, so that a token added to the request by an intermediary is not
     * disclosed to the OpenID provider.
     *
     * @param request The HTTP Request
     * @param authentication The authentication
     * @return An ID token if it could be resolved
     */
    protected Optional<String> parseIdToken(HttpRequest<?> request, Authentication authentication) {
        Map<String, Object> attributes = authentication.getAttributes();
        if (attributes.containsKey(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY)) {
            return Optional.of(attributes.get(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY).toString());
        }
        if (securityConfiguration.getAuthentication() == AuthenticationMode.IDTOKEN) {
            return authenticatingToken(request);
        }
        return Optional.empty();
    }

    /**
     * Returns the token which authenticated the request, as recorded in the {@link SecurityFilter#TOKEN} request attribute by the authentication fetcher.
     * Only this token is a candidate for {@code id_token_hint}: in {@link AuthenticationMode#IDTOKEN} mode the user authenticates with
     * the ID token, so the authenticating token is the ID token. If no token authenticated the request, an empty optional is returned
     * and no {@code id_token_hint} is sent.
     *
     * @param request The HTTP Request
     * @return The token which authenticated the request, if any
     * @since 3.11.3
     */
    @NonNull
    protected Optional<String> authenticatingToken(@NonNull HttpRequest<?> request) {
        String token = request.getAttribute(SecurityFilter.TOKEN, String.class).orElse(null);
        if (token == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No token authenticated the request {} {}. id_token_hint will not be sent to the end session endpoint", request.getMethod(), request.getPath());
            }
            return Optional.empty();
        }
        return Optional.of(token);
    }
}


