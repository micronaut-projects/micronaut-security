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
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.Introspected;

import java.util.HashMap;
import java.util.Map;

/**
 * @see <a href="https://tools.ietf.org/html/rfc7662#section-2.2">RFC7622 Introspection Response</a>
 * @author Sergio del Amo
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Introspected
public class IntrospectionResponse {

    /**
     * Boolean indicator of whether or not the presented token is currently active.
     */
    private boolean active;

    /**
     *  A JSON string containing a space-separated list of scopes associated with this token.
     */
    @Nullable
    private String scope;

    /**
     * Client identifier for the OAuth 2.0 client that requested this token.
     */
    @JsonProperty("client_id")
    @Nullable
    private String clientId;

    /**
     * Human-readable identifier for the resource owner who authorized this token.
     */
    @Nullable
    private String username;

    /**
     * Type of token.
     */
    @JsonProperty("token_type")
    private String tokenType;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire as defined in JWT.
     */
    @Nullable
    private Long exp;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    @Nullable
    private Long iat;

    /**
     * Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT.
     */
    @Nullable
    private Long nbf;

    /**
     * Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner who authorized this token.
     */
    @Nullable
    private String sub;

    /**
     * Service-specific string identifier or list of string identifiers representing the intended audience for this token, as defined in JWT.
     */
    @Nullable
    private String aud;

    /**
     * String representing the issuer of this token, as defined in JWT.
     */
    @Nullable
    private String iss;

    /**
     * String identifier for the token, as defined in JWT.
     */
    @Nullable
    private String jti;

    private Map<String, Object> extensions = new HashMap<>();

    /**
     * Constructor.
     */
    public IntrospectionResponse() {
    }

    /**
     *
     * @param active Boolean indicator of whether or not the presented token is currently active.
     */
    public IntrospectionResponse(boolean active) {
        this.active = active;
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
     * @param extensions Extensions
     */
    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions;
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
     * @param active Boolean indicator of whether or not the presented token is currently active.
     */
    public void setActive(boolean active) {
        this.active = active;
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
     * @param scope A JSON string containing a space-separated list of scopes associated with this token.
     */
    public void setScope(@Nullable String scope) {
        this.scope = scope;
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
     * @param clientId Client identifier for the OAuth 2.0 client that requested this token.
     */
    public void setClientId(@Nullable String clientId) {
        this.clientId = clientId;
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
     * @param username Human-readable identifier for the resource owner who authorized this token.
     */
    public void setUsername(@Nullable String username) {
        this.username = username;
    }

    /**
     *
     * @return Type of token.
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     *
     * @param tokenType Type of token.
     */
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
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
     * @param exp Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire as defined in JWT.
     */
    public void setExp(@Nullable Long exp) {
        this.exp = exp;
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
     * @param iat Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    public void setIat(@Nullable Long iat) {
        this.iat = iat;
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
     * @param nbf Long timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT.
     */
    public void setNbf(@Nullable Long nbf) {
        this.nbf = nbf;
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
     * @param sub Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner who authorized this token.
     */
    public void setSub(@Nullable String sub) {
        this.sub = sub;
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
     * @param aud Service-specific string identifier or list of string identifiers representing the intended audience for this token, as defined in JWT
     */
    public void setAud(@Nullable String aud) {
        this.aud = aud;
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
     * @param iss Long timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT.
     */
    public void setIss(@Nullable String iss) {
        this.iss = iss;
    }

    /**
     *
     * @return String identifier for the token, as defined in JWT.
     */
    @Nullable
    public String getJti() {
        return jti;
    }

    /**
     *
     * @param jti String identifier for the token, as defined in JWT.
     */
    public void setJti(@Nullable String jti) {
        this.jti = jti;
    }
}
