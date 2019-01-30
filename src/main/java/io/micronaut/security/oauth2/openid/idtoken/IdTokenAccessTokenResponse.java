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

package io.micronaut.security.oauth2.openid.idtoken;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.security.oauth2.responses.AccessTokenResponse;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;

/**
 * Id Token Access Token Response.
 *
 * After receiving and validating a valid and authorized Token Request from the Client, the Authorization Server returns a successful response that includes an ID Token and an Access Token.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse>Successful Token Response</a>
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class IdTokenAccessTokenResponse extends AccessTokenResponse {

    @Nonnull
    @JsonProperty("id_token")
    private String idToken;

    /**
     * Instantiates ID Token Access Token Response.
     */
    public IdTokenAccessTokenResponse() {

    }

    /**
     *
     * @param m A Map e.g a JSON response.
     * @return null if the required properties are not found in the map, an AccessTokenResponse otherwise.
     */
    @Nullable
    public static AccessTokenResponse of(@Nonnull Map<String, Object> m) {
        if (containsRequiredParameters(m)) {
            IdTokenAccessTokenResponse accessTokenResponse = new IdTokenAccessTokenResponse();
            accessTokenResponse.populateWithMap(m);
            accessTokenResponse.setIdToken((String) m.get("id_token"));
            return accessTokenResponse;

        }
        return null;
    }

    /**
     *
     * @param m A Map e.g a JSON response.
     * @return true if the map keys contain the required parameters
     */
    protected static boolean containsRequiredParameters(@Nonnull Map<String, Object> m) {
        boolean superContains = AccessTokenResponse.containsRequiredParameters(m);
        return superContains && (m.containsKey("id_token") && (m.get("id_token") instanceof String));
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
