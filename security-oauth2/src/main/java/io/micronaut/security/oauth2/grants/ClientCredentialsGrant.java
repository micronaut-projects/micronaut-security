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
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
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
public class ClientCredentialsGrant extends AbstractSecureGrant implements AsMap {

    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_SCOPE = "scope";

    private String grantType = GrantType.CLIENT_CREDENTIALS.toString();
    private String scope;

    /**
     * Default Constructor.
     */
    public ClientCredentialsGrant() {
    }

    /**
     * @param clientConfiguration The client configuration
     */
    public ClientCredentialsGrant(OauthClientConfiguration clientConfiguration) {
        scope = clientConfiguration.getScopes().stream()
                .reduce((a, b) -> a + StringUtils.SPACE + b)
                .orElse(null);
    }

    /**
     * @return client_credentials
     */
    @NonNull
    public String getGrantType() {
        return grantType;
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
    public Map<String, String> toMap() {
        Map<String, String> m = new SecureGrantMap(4, getClientId(), getClientSecret());
        m.put(KEY_GRANT_TYPE, getGrantType());
        String scope = getScope();
        if (StringUtils.isNotEmpty(scope)) {
            m.put(KEY_SCOPE, scope);
        }
        return m;
    }
}
