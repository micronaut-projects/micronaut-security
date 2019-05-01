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

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

/**
 * Client Credentials Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class ClientCredentialsGrant implements AsMap {

    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_SCOPES = "scopes";

    private String grantType = GrantType.CLIENT_CREDENTIALS.toString();
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

    /**
     *
     * @return this object as a Map
     */
    @Override
    public Map<String, String> toMap() {
        Map<String, String> m = new HashMap<>(2);
        m.put(KEY_GRANT_TYPE, getGrantType());
        m.put(KEY_SCOPES, getScope());
        return m;
    }
}
