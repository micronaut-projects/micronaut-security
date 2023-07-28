/*
 * Copyright 2017-2023 original authors
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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

/**
 * Client Credentials Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
public class ClientCredentialsGrant extends AbstractClientSecureGrant implements SecureGrant, AsMap {

    public static final String KEY_SCOPES = "scope";

    @JsonProperty("grant_type")
    @NonNull
    @NotBlank
    private String grantType = GrantType.CLIENT_CREDENTIALS.toString();

    @Nullable
    private String scope;

    /**
     *
     * @return Grant Type.
     */
    @NonNull
    @Override
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType Grant type
     */
    @Override
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
     * @return this object as a Map
     */
    @Override
    @NonNull
    public Map<String, String> toMap() {
        Map<String, String> m = super.toMap();
        if (StringUtils.isNotEmpty(scope)) {
            m.put(KEY_SCOPES, scope);
        }
        return m;
    }

}
