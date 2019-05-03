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

package io.micronaut.security.oauth2.endpoint.token.response;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import javax.annotation.Nonnull;

/**
 * Id Token Access Token Response.
 *
 * After receiving and validating a valid and authorized Token Request from the Client, the Authorization Server returns a successful response that includes an ID Token and an Access Token.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse>Successful Token Response</a>
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class DefaultOpenIdTokenResponse extends DefaultTokenResponse implements OpenIdTokenResponse {

    private String idToken;

    /**
     * Instantiates ID Token Access Token Response.
     */
    public DefaultOpenIdTokenResponse() {

    }

    /**
     *
     * @return ID Token value associated with the authenticated session.
     */
    @Nonnull
    public String getIdToken() {
        return idToken;
    }

    /**
     *
     * @param idToken ID Token value associated with the authenticated session.
     */
    public void setIdToken(@Nonnull String idToken) {
        this.idToken = idToken;
    }
}
