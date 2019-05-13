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

package io.micronaut.security.oauth2.endpoint.introspection;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import io.reactivex.annotations.NonNull;
import io.reactivex.annotations.Nullable;

import javax.validation.constraints.NotNull;

/**
 * Introspection Response.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7662#section-2.2">Introspection Response</a>.
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
public class IntrospectionResponse implements TokenValidationResponse {

    @NotNull
    @NonNull
    private boolean active;

    @Nullable
    private String scope;

    @Nullable
    @JsonProperty("client_id")
    private String clientId;

    @Nullable
    private String username;

    @Nullable
    @JsonProperty("token_type")
    private String tokenType;

    @Nullable
    private Integer exp;

    @Nullable
    private Integer iat;

    @Nullable
    private Integer nbf;

    @Nullable
    private String sub;

    @Nullable
    private String aud;

    @Nullable
    private String iss;

    @Nullable
    private String jti;

    /**
     * Constructor.
     */
    public IntrospectionResponse() {

    }

    /**
     *
     * @return Whether or not the presented token is currently active.
     */
    @Override
    public boolean isActive() {
        return active;
    }

    /**
     *
     * @param active  Whether or not the presented token is currently active.
     */
    public void setActive(boolean active) {
        this.active = active;
    }

    /**
     *
     * @return A JSON string containing a space-separated list of scopes associated with this token
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope A JSON string containing a space-separated list of scopes associated with this token
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
     * @return Type of the token
     */
    @Nullable
    public String getTokenType() {
        return tokenType;
    }

    /**
     *
     * @param tokenType Type of the token
     */
    public void setTokenType(@Nullable String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     *
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire, as defined in JWT
     */
    @Nullable
    public Integer getExp() {
        return exp;
    }

    /**
     *
     * @param exp Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire, as defined in JWT
     */
    public void setExp(@Nullable Integer exp) {
        this.exp = exp;
    }

    /**
     *
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT
     */
    @Nullable
    public Integer getIat() {
        return iat;
    }

    /**
     *
     * @param iat Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT
     */
    public void setIat(@Nullable Integer iat) {
        this.iat = iat;
    }

    /**
     *
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT
     */
    @Nullable
    public Integer getNbf() {
        return nbf;
    }

    /**
     *
     * @param nbf Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT
     */
    public void setNbf(@Nullable Integer nbf) {
        this.nbf = nbf;
    }

    /**
     *
     * @return Subject of the token
     */
    @Nullable
    public String getSub() {
        return sub;
    }

    /**
     *
     * @param sub Subject of the token
     */
    public void setSub(@Nullable String sub) {
        this.sub = sub;
    }

    /**
     *
     * @return Service-specific string identifier or list of string identifiers representing the intended audience for this token
     */
    @Nullable
    public String getAud() {
        return aud;
    }

    /**
     *
     * @param aud  Service-specific string identifier or list of string identifiers representing the intended audience for this token
     */
    public void setAud(@Nullable String aud) {
        this.aud = aud;
    }

    /**
     *
     * @return String representing the issuer of this token
     */
    @Nullable
    public String getIss() {
        return iss;
    }

    /**
     *
     * @param iss String representing the issuer of this token
     */
    public void setIss(@Nullable String iss) {
        this.iss = iss;
    }

    /**
     *
     * @return String identifier for the token
     */
    @Nullable
    public String getJti() {
        return jti;
    }

    /**
     *
     * @param jti String identifier for the token
     */
    public void setJti(@Nullable String jti) {
        this.jti = jti;
    }
}
