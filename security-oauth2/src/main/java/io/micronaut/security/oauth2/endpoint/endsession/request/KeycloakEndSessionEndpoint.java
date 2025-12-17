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
package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.core.util.StringUtils;
import io.micronaut.core.version.SemanticVersion;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Provides specific configuration to logout from Keycloak.
 *
 * @author Lukas Moravec
 * @author Knut Olav Bøhmer
 * @see <a href="https://www.keycloak.org/docs/latest/server_admin/#rp-initiated-logout">Keycloak Logout Documentation</a>
 * @since 3.2.0
 */
public class KeycloakEndSessionEndpoint extends AbstractEndSessionRequest {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakEndSessionEndpoint.class);
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String LOGOUT_URI = "/protocol/openid-connect/logout";
    private static final SemanticVersion KEYCLOAK_18 = new SemanticVersion("18.0.0");

    /**
     * @param endSessionCallbackUrlBuilder The end session callback URL builder
     * @param clientConfiguration          The client configuration
     * @param providerMetadata             The provider metadata supplier
     */
    public KeycloakEndSessionEndpoint(EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                      OauthClientConfiguration clientConfiguration,
                                      Supplier<OpenIdProviderMetadata> providerMetadata) {
        super(endSessionCallbackUrlBuilder, clientConfiguration, providerMetadata);
    }

    @Override
    protected String getUrl() {
        OpenIdProviderMetadata openIdProviderMetadata = providerMetadataSupplier.get();
        return openIdProviderMetadata.getEndSessionEndpoint() != null ?
            openIdProviderMetadata.getEndSessionEndpoint() :
            StringUtils.prependUri(openIdProviderMetadata.getIssuer(), LOGOUT_URI);
    }

    @Override
    protected Map<String, Object> getArguments(HttpRequest<?> originating,
                                               Authentication authentication) {
        Map<String, Object> arguments = new HashMap<>();
        String redirectUri = getRedirectUri(originating);

        populateHints(arguments, authentication);

        if (isLegacyLogout()) {
            arguments.put(PARAM_REDIRECT_URI, redirectUri);
        } else if (StringUtils.isNotEmpty(redirectUri)) {
            arguments.put(PARAM_POST_LOGOUT_REDIRECT_URI, redirectUri);
        }

        return arguments;
    }

    /**
     * Populates id_token_hint or client_id to ensure seamless logout.
     */
    private void populateHints(Map<String, Object> arguments, Authentication authentication) {
        if (authentication == null) {
            return;
        }

        Object idToken = authentication.getAttributes().get(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY);

        if (idToken != null) {
            arguments.put(PARAM_ID_TOKEN_HINT, idToken.toString());
        } else {
            arguments.put(PARAM_CLIENT_ID, clientConfiguration.getClientId());

            if (LOG.isDebugEnabled()) {
                LOG.debug("ID Token not found in Authentication attributes. Logout will fallback to " +
                    "interactive confirmation. To enable seamless logout, set " +
                    "'micronaut.security.oauth2.openid.additional-claims.jwt=true'.");
            }
        }
    }

    /**
     * Determines if legacy logout (redirect_uri) should be used.
     * Defaults to modern logout when version is missing/blank.
     *
     * @return true if configured version is < 18.0.0
     */
    private boolean isLegacyLogout() {
        String v = clientConfiguration.getVersion();
        if (v == null || v.isBlank()) return false;

        try {
            return new SemanticVersion(v.trim()).compareTo(KEYCLOAK_18) < 0;
        } catch (IllegalArgumentException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid Keycloak version '{}'. Expected d.d.d (semver). Falling back to modern logout.",
                    v);
            }
            return false;
        }
    }
}
