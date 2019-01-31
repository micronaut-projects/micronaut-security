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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.openid.OpenIdScope;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;

/**
 * {@link ConfigurationProperties} implementation of {@link GrantTypePasswordRequestProviderConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(GrantTypePasswordRequestProviderConfigurationProperties.PREFIX)
public class GrantTypePasswordRequestProviderConfigurationProperties implements GrantTypePasswordRequestProviderConfiguration  {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".grant-type-password";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = false;

    /**
     * Default scope.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_SCOPE = OpenIdScope.OPENID.getScope();

    /**
     * Default Grant Type.
     */
    @SuppressWarnings("WeakerAccess")
    public static final MediaType DEFAULT_CONTENT_TYPE = MediaType.APPLICATION_FORM_URLENCODED_TYPE;

    private boolean enabled = DEFAULT_ENABLED;

    @Nonnull
    private MediaType contentType = DEFAULT_CONTENT_TYPE;

    @Nonnull
    private List<String> scopes = Collections.singletonList(DEFAULT_SCOPE);

    /**
     * @return true if you want to enable the {@link GrantTypePasswordRequestProvider}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link GrantTypePasswordRequestProvider} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Nonnull
    @Override
    public MediaType getContentType() {
        return this.contentType;
    }

    /**
     * The Content-Type used to communicate with the token endpoint.
     * @param contentType The Content-Type
     */
    public void setContentType(@Nonnull MediaType contentType) {
        this.contentType = contentType;
    }

    @Override
    @Nonnull
    public List<String> getScopes() {
        return scopes;
    }

    /**
     *
     * @param scopes OAuth 2.0 scopes.
     */
    public void setScopes(@Nonnull List<String> scopes) {
        this.scopes = scopes;
    }
}
