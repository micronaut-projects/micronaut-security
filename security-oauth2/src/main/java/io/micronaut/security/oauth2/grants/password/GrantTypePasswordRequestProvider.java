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

package io.micronaut.security.oauth2.grants.password;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.grants.PasswordGrant;
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Objects;

/**
 * Generates a HTTP request to the token endpoint for password grant type.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = {
        GrantTypePasswordRequestProviderConfiguration.class,
        OauthClientConfiguration.class,
        OpenIdEndpoints.class,
})
@Requires(property = GrantTypePasswordRequestProviderConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE)
@Singleton
public class GrantTypePasswordRequestProvider {

    private final GrantTypePasswordRequestProviderConfiguration grantTypePasswordRequestProviderConfiguration;
    private final OauthClientConfiguration oauthConfiguration;
    private final OpenIdEndpoints openIdEndpoints;

    /**
     *
     * @param oauthConfiguration Oauth Configuration
     * @param openIdEndpoints OpenID endpoints
     * @param grantTypePasswordRequestProviderConfiguration {@link GrantTypePasswordRequestProvider} configuration
     */
    public GrantTypePasswordRequestProvider(OauthClientConfiguration oauthConfiguration,
                                            OpenIdEndpoints openIdEndpoints,
                                            GrantTypePasswordRequestProviderConfiguration grantTypePasswordRequestProviderConfiguration) {
        this.oauthConfiguration = oauthConfiguration;
        this.openIdEndpoints = openIdEndpoints;
        this.grantTypePasswordRequestProviderConfiguration = grantTypePasswordRequestProviderConfiguration;
    }

    /**
     *
     * @param username User's username
     * @param password User's password
     * @return an HTTP request
     */
    public HttpRequest generateRequest(@Nonnull String username, @Nonnull String password) {
        PasswordGrant grant = generatePasswordGrant(username, password);
        Object body = grantTypePasswordRequestProviderConfiguration.getContentType().equals(MediaType.APPLICATION_FORM_URLENCODED_TYPE) ? grant.toMap() : grant;
        return HttpRequest.POST(Objects.requireNonNull(openIdEndpoints.getToken()), body).contentType(grantTypePasswordRequestProviderConfiguration.getContentType());
    }

    /**
     *
     * @param username User's username
     * @param password User's password
     * @return A populated {@link PasswordGrant} object.
     */
    protected PasswordGrant generatePasswordGrant(@Nonnull String username, @Nonnull String password) {
        PasswordGrant passwordGrant = new PasswordGrant();
        passwordGrant.setClientId(oauthConfiguration.getClientId());
        passwordGrant.setClientSecret(oauthConfiguration.getClientSecret());
        passwordGrant.setUsername(username);
        passwordGrant.setPassword(password);
        grantTypePasswordRequestProviderConfiguration.getScopes().stream().reduce((a, b) -> a + StringUtils.SPACE + b).ifPresent(scope -> passwordGrant.setScope(scope));
        return passwordGrant;
    }
}
