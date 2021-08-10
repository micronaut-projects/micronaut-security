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
package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;

import javax.validation.constraints.NotBlank;
import java.util.Map;

/**
 * Client Credentials Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class ClientCredentialsGrant implements SecureGrant, AsMap {

    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_SCOPES = "scope";
    public static final String KEY_AUDIENCE = "audience";

    @NonNull
    @NotBlank
    private String grantType = GrantType.CLIENT_CREDENTIALS.toString();

    @Nullable
    private String scope;

    @Nullable
    private String clientId;

    @Nullable
    private String clientSecret;

    @Nullable
    private String audience;

    /**
     * Default Constructor.
     */
    public ClientCredentialsGrant() {
    }

    /**
     * @return client_credentials
     */
    @NonNull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType Grant type
     */
    public void setGrantType(@NonNull String grantType) {
        this.grantType = grantType;
    }

    /**
     * @return Requested scope values for the access token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     * @param scope Requested scope values for the access token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return The application's Client identifier.
     */
    @NonNull
    public String getClientId() {
        return clientId;
    }

    /**
     *
     * @param clientId Application's Client identifier.
     */
    public void setClientId(@NonNull String clientId) {
        this.clientId = clientId;
    }

    /**
     *
     * @param clientSecret Application's Client clientSecret.
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     *
     * @return The application's Client clientSecret.
     */
    public String getClientSecret() {
        return this.clientSecret;
    }

    /**
     * @return The application's audience
     */
    @Nullable
    public String getAudience() {
        return audience;
    }

    /**
     * @param audience The application's audience
     */
    public void setAudience(@Nullable String audience) {
        this.audience = audience;
    }

    /**
     * @return this object as a Map
     */
    @Override
    public Map<String, String> toMap() {
        Map<String, String> m = new SecureGrantMap(2);
        m.put(KEY_GRANT_TYPE, getGrantType());
        if (StringUtils.isNotEmpty(scope)) {
            m.put(KEY_SCOPES, scope);
        }
        if (clientId != null) {
            m.put(KEY_CLIENT_ID, clientId);
        }
        if (clientSecret != null) {
            m.put(KEY_CLIENT_SECRET, clientSecret);
        }
        if (StringUtils.isNotEmpty(audience)) {
            m.put(KEY_AUDIENCE, audience);
        }
        return m;
    }

}
