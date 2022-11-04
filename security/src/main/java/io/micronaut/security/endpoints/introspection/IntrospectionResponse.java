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
package io.micronaut.security.endpoints.introspection;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;
import java.util.HashMap;
import java.util.Map;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7662#section-2.2">RFC7622 Introspection Response</a>
 * @author Sergio del Amo
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Serdeable
public class IntrospectionResponse {

    /**
     * Boolean indicator of whether or not the presented token is currently active.
     */
    private final boolean active;

    /**
     * A JSON string containing a space-separated list of scopes associated with this token.
     */
    @Nullable
    private final String scope;

    /**
     * Client identifier for the OAuth 2.0 client that requested this token.
     */
    @JsonProperty("client_id")
    @Nullable
    private final String clientId;

    /**
     * Human-readable identifier for the resource owner who authorized this token.
     */
    @Nullable
    private final String username;

    /**
     * Type of token.
     */
    @JsonProperty("token_type")
    @Nullable
    private final String tokenType;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire as defined in JWT.
     */
    @Nullable
    private final Long exp;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    @Nullable
    private final Long iat;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT.
     */
    @Nullable
    private final Long nbf;

    /**
     * Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner who authorized this token.
     */
    @Nullable
    private final String sub;

    /**
     * Service-specific string identifier or list of string identifiers representing the intended audience for this token, as defined in JWT.
     */
    @Nullable
    private final String aud;

    /**
     * String representing the issuer of this token, as defined in JWT.
     */
    @Nullable
    private final String iss;

    /**
     * String identifier for the token, as defined in JWT.
     */
    @Nullable
    private final String jti;

    @NonNull
    private final Map<String, Object> extensions = new HashMap<>();

    /**
     *
     * @param active Boolean indicator of whether or not the presented token is currently active.
     * @param tokenType Type of token.
     * @param scope A JSON string containing a space-separated list of scopes associated with this token.
     * @param clientId Client identifier for the OAuth 2.0 client that requested this token.
     * @param username Human-readable identifier for the resource owner who authorized this token.
     * @param exp Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire as defined in JWT.
     * @param iat Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     * @param nbf Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT.
     * @param sub Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner who authorized this token.
     * @param aud Service-specific string identifier or list of string identifiers representing the intended audience for this token, as defined in JWT.
     * @param iss String representing the issuer of this token, as defined in JWT.
     * @param jti String identifier for the token, as defined in JWT.
     * @param extensions Extensions
     */
    @SuppressWarnings("ParameterNumber")
    public IntrospectionResponse(boolean active,
                                 @Nullable String tokenType,
                                 @Nullable String scope,
                                 @Nullable String clientId,
                                 @Nullable String username,
                                 @Nullable Long exp,
                                 @Nullable Long iat,
                                 @Nullable Long nbf,
                                 @Nullable String sub,
                                 @Nullable String aud,
                                 @Nullable String iss,
                                 @Nullable String jti,
                                 @Nullable Map<String, Object> extensions) {
        this.active = active;
        this.tokenType = tokenType;
        this.scope = scope;
        this.clientId = clientId;
        this.username = username;
        this.exp = exp;
        this.iat = iat;
        this.nbf = nbf;
        this.sub = sub;
        this.aud = aud;
        this.iss = iss;
        this.jti = jti;
        if (extensions != null) {
            this.extensions.putAll(extensions);
        }
    }

    /**
     *
     * @param key Key
     * @param value Value
     */
    @JsonAnySetter
    public void addExtension(String key, Object value) {
        this.extensions.put(key, value);
    }

    /**
     *
     * @return Extensions
     */
    @JsonAnyGetter
    public Map<String, Object> getExtensions() {
        return extensions;
    }

    /**
     *
     * @return Boolean indicator of whether or not the presented token is currently active.
     */
    public boolean isActive() {
        return active;
    }

    /**
     *
     * @return A JSON string containing a space-separated list of scopes associated with this token.
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @return Client identifier for the OAuth 2.0 client that requested this token.
     */
    @Nullable
    public String getClientId() {
        return clientId;
    }

    /**
     *
     * @return Human-readable identifier for the resource owner who authorized this token.
     */
    @Nullable
    public String getUsername() {
        return username;
    }

    /**
     *
     * @return Type of token.
     */
    @Nullable
    public String getTokenType() {
        return tokenType;
    }

    /**
     *
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire as defined in JWT.
     */
    @Nullable
    public Long getExp() {
        return exp;
    }

    /**
     *
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    @Nullable
    public Long getIat() {
        return iat;
    }

    /**
     *
     * @return Long timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT.
     */
    @Nullable
    public Long getNbf() {
        return nbf;
    }

    /**
     *
     * @return Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner who authorized this token.
     */
    @Nullable
    public String getSub() {
        return sub;
    }

    /**
     *
     * @return Service-specific string identifier or list of string identifiers representing the intended audience for this token, as defined in JWT
     */
    @Nullable
    public String getAud() {
        return aud;
    }

    /**
     *
     * @return Long timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    @Nullable
    public String getIss() {
        return iss;
    }

    /**
     *
     * @return String identifier for the token, as defined in JWT.
     */
    @Nullable
    public String getJti() {
        return jti;
    }
}
