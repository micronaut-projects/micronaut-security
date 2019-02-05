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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.handlers.UnauthorizedRejectionUriProvider;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationRedirectUrlProvider;
import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * Provides an implementation of {@link UnauthorizedRejectionUriProvider} to redirect to the authorization url provide by {@link AuthorizationRedirectUrlProvider}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = AuthorizationRedirectUrlProvider.class)
@Requires(property = OpenIdUnauthorizedRejectionUriProvider.PREFIX, notEquals = StringUtils.FALSE)
@Singleton
public class OpenIdUnauthorizedRejectionUriProvider implements UnauthorizedRejectionUriProvider {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".unauthorized-rejection-uri-provider.enabled";

    @Nonnull
    private final AuthorizationRedirectUrlProvider authorizationRedirectUrlProvider;

    /**
     *
     * @param authorizationRedirectUrlProvider Authorization Redirect Url Provider
     */
    public OpenIdUnauthorizedRejectionUriProvider(@Nonnull AuthorizationRedirectUrlProvider authorizationRedirectUrlProvider) {
        this.authorizationRedirectUrlProvider = authorizationRedirectUrlProvider;

    }

    @Override
    public Optional<String> getUnauthorizedRedirectUri(HttpRequest<?> request) {
        return Optional.of(authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl(request));
    }
}
