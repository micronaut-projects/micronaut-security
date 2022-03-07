/*
 * Copyright 2017-2022 original authors
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

import io.micronaut.core.annotation.NonNull;

import java.util.Map;

/**
 * Base class for {@link SecureGrant} implementations.
 *
 * @author Álvaro Sánchez-Mariscal
 */
public abstract class AbstractClientSecureGrant implements SecureGrant, AsMap {

    private static final String KEY_GRANT_TYPE = "grant_type";

    protected String clientId;
    protected String clientSecret;

    /**
     *
     * @return OAuth 2.0 Grant Type.
     */
    @NonNull
    public abstract String getGrantType();

    /**
     *
     * @param grantType OAuth 2.0 Grant Type.
     */
    public abstract void setGrantType(@NonNull String grantType);

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
     * @return this object as a Map
     */
    @Override
    public Map<String, String> toMap() {
        Map<String, String> m = new SecureGrantMap();
        m.put(KEY_GRANT_TYPE, getGrantType());
        if (clientId != null) {
            m.put(KEY_CLIENT_ID, clientId);
        }
        if (clientSecret != null) {
            m.put(KEY_CLIENT_SECRET, clientSecret);
        }
        return m;
    }


}
