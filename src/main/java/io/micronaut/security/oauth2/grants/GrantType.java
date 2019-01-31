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

package io.micronaut.security.oauth2.grants;

/**
 * The OAuth 2.0 grant types.
 * @see <a href="https://oauth.net/2/grant-types/">OAuth 2.0 Grant Types</a>
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
public enum GrantType {

    /**
     * The Client Credentials grant type is used by clients to obtain an access token outside of the context of a user.
     *
     * This is typically used by clients to access resources about themselves rather than to access a user's resources.
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.3.4">Client Credentials</a>
     */
    CLIENT_CREDENTIALS("client_credentials"),

    /**
     * The Authorization Code grant type is used by confidential and public clients to exchange
     * an authorization code for an access token.
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.3.1">Authorization code</a>
     */
    AUTHORIZATION_CODE("authorization_code"),

    /**
     *  Oauth 2.0 refresh tokens.
     *
     *  Refresh tokens are issued to the client by the authorization server and are
     *  used to obtain a new access token when the current access token
     *  becomes invalid or expires, or to obtain additional access tokens
     *  with identical or narrower scope.
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.5">Refresh Token</a>
     */
    REFRESH_TOKEN("refresh_token"),

    /**
     * The implicit grant is a simplified authorization code flow optimized
     * for clients implemented in a browser using a scripting language such
     * as JavaScript.  In the implicit flow, instead of issuing the client
     * an authorization code, the client is issued an access token directly
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.3.2">Implicit</a>
     */
    IMPLICIT("implicit"),

    /**
     * The Password grant type is used by first-party clients to exchange a user's credentials for an access token.
     * <a href="https://tools.ietf.org/html/rfc6749#section-1.3.3">Resource Owner Password Credentials</a>
     */
    PASSWORD("password"),

    JWT_BEARER_ASSERTION_GRANT("urn:ietf:params:oauth:grant-type:jwt-bearer"),

    SAML_2_0_BEARER_ASSERTION_GRANT("urn:ietf:params:oauth:grant-type:saml2-bearer");

    private String grantType;

    /**
     *
     * @param grantType The Oauth 2.0. Grant Type
     */
    GrantType(String grantType) {
        this.grantType = grantType;
    }

    /**
     *
     * @return The Oauth 2.0. Grant Type
     */
    public String getGrantType() {
        return this.grantType;
    }
}
