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

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;

import java.util.Map;

/**
 * Authorization Code Grant Request.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class AuthorizationCodeGrant extends AbstractClientSecureGrant implements SecureGrant, AsMap {

    private static final String KEY_REDIRECT_URI = "redirect_uri";
    private static final String KEY_CODE = "code";

    private String grantType = GrantType.AUTHORIZATION_CODE.toString();
    private String redirectUri;
    private String code;

    /**
     *
     * @return OAuth 2.0 Grant Type.
     */
    @NonNull
    @Override
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType OAuth 2.0 Grant Type.
     */
    @Override
    public void setGrantType(@NonNull String grantType) {
        this.grantType = grantType;
    }

    /**
     *
     * @return Redirection URI to which the response will be sent.
     */
    @NonNull
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     *
     * @param redirectUri Redirection URI to which the response will be sent.
     */
    public void setRedirectUri(@NonNull String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /**
     *
     * @return An authorization code.
     */
    @NonNull
    public String getCode() {
        return code;
    }

    /**
     *
     * @param code An authorization code.
     */
    public void setCode(@NonNull String code) {
        this.code = code;
    }

    /**
     *
     * @return this object as a Map
     */
    @Override
    public Map<String, String> toMap() {
        Map<String, String> m = super.toMap();
        m.put(KEY_CODE, getCode());
        if (redirectUri != null) {
            m.put(KEY_REDIRECT_URI, getRedirectUri());
        }
        return m;
    }

}
