/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.context.annotation.DefaultImplementation;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import org.reactivestreams.Publisher;

/**
 * Validates an OpenID token response.
 *
 * @author Sergio del Amo
 * @since 4.8.0
 * @param <T> token
 */
@DefaultImplementation(DefaultReactiveOpenIdTokenResponseValidator.class)
public interface ReactiveOpenIdTokenResponseValidator<T> {

    /**
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * @param nonce The persisted nonce value
     * @return A non-empty publisher if the ID Token access response is considered valid
     */
    @SingleResult
    @NonNull
    Publisher<T> validate(@NonNull OauthClientConfiguration clientConfiguration,
                          @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                          @NonNull OpenIdTokenResponse openIdTokenResponse,
                          @Nullable String nonce);

    /**
     * Validates an OpenID token response obtained without an authorization request, for example with the password
     * grant. No nonce is sent in such flows, so there is no persisted nonce to compare the ID token with.
     *
     * <p>The default implementation delegates to
     * {@link #validate(OauthClientConfiguration, OpenIdProviderMetadata, OpenIdTokenResponse, String)} with a
     * {@code null} nonce.</p>
     *
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * @return A non-empty publisher if the ID Token access response is considered valid
     * @since 5.5.3
     */
    @SingleResult
    @NonNull
    default Publisher<T> validateWithoutNonce(@NonNull OauthClientConfiguration clientConfiguration,
                                              @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                              @NonNull OpenIdTokenResponse openIdTokenResponse) {
        return validate(clientConfiguration, openIdProviderMetadata, openIdTokenResponse, null);
    }
}
