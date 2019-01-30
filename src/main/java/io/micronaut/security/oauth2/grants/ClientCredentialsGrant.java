/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Client Credentials Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class ClientCredentialsGrant {

    @Nonnull
    @JsonProperty("grant_type")
    private String grantType = GrantType.CLIENT_CREDENTIALS.getGrantType();

    @Nullable
    private String scope;

    /**
     * Instantiate ClientCredentialsGrant.
     */
    public ClientCredentialsGrant() {

    }

    /**
     *
     * @return client_credentials
     */
    @Nonnull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @return Requested scope values for the access token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope Requested scope values for the access token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
    }
}
