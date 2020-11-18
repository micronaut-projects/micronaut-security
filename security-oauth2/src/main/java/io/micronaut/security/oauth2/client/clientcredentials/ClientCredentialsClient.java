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
package io.micronaut.security.oauth2.client.clientcredentials;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;

/**
 * @author Sergio del Amo
 * @since 2.2.0
 */
public interface ClientCredentialsClient {

    /**
     *
     * @param scope Requested scope values for the access token.
     * @return Response of an authorization server to a valid client credentials request.
     */
    @NonNull
    Publisher<TokenResponse> requestToken(@Nullable String scope);

    /**
     *
     * @param scope Requested scope values for the access token.
     * @param force true to invalidate the cached token response and fetch a new one
     * @return Response of an authorization server to a valid client credentials request.
     */
    @NonNull
    Publisher<TokenResponse> requestToken(@Nullable String scope, boolean force);

    /**
     *
     * @return Response of an authorization server to a valid client credentials request.
     */
    @NonNull
    default Publisher<TokenResponse> requestToken() {
        return requestToken(null);
    }

    /**
     * @param force true to invalidate the cached token response and fetch a new one
     * @return Response of an authorization server to a valid client credentials request.
     */
    @NonNull
    default Publisher<TokenResponse> requestToken(boolean force) {
        return requestToken(null, force);
    }
}
