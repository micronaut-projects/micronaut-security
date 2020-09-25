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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.annotation.Introspected;

import javax.validation.constraints.NotBlank;

/**
 * A parameter representing the token along with optional parameters representing
 * additional context that is known by the protected resource to aid the authorization server in its response.
 * @see <a href="https://tools.ietf.org/html/rfc7662#section-2.1">RFC7662 2.1. Introspection request</a>
 * @author Sergio del Amo
 * @since 2.1.0
 */
@Introspected
public class IntrospectionRequest {

    /**
     *  The string value of the token.
     */
    @NonNull
    @NotBlank
    private String token;

    /**
     * A hint about the type of the token submitted for introspection.
     */
    @Nullable
    private String token_type_hint;

    /**
     * Constructor.
     */
    public IntrospectionRequest() {
    }

    /**
     *
     * @param token The string value of the token
     */
    public IntrospectionRequest(@NonNull @NotBlank String token) {
        this.token = token;
    }

    /**
     *
     * @param token The string value of the token
     * @param tokenTypeHint A hint about the type of the token submitted for introspection.
     */
    public IntrospectionRequest(@NonNull @NotBlank String token, @Nullable String tokenTypeHint) {
        this.token = token;
        this.token_type_hint = tokenTypeHint;
    }

    /**
     *
     * @return  The string value of the token
     */
    @NonNull
    public String getToken() {
        return token;
    }

    /**
     *
     * @param token  The string value of the tok
     */
    public void setToken(@NonNull String token) {
        this.token = token;
    }

    /**
     *
     * @return A hint about the type of the token submitted for introspection.
     */
    @Nullable
    public String getTokenTypeHint() {
        return token_type_hint;
    }

    /**
     *
     * @param tokenTypeHint A hint about the type of the token submitted for introspection.
     */
    public void setTokenTypeHint(@Nullable String tokenTypeHint) {
        this.token_type_hint = tokenTypeHint;
    }

    /**
     *
     * @return A hint about the type of the token submitted for introspection.
     */
    @Nullable
    @SuppressWarnings("MethodName")
    public String getToken_type_hint() {
        return token_type_hint;
    }

    /**
     *
     * @param tokenTypeHint A hint about the type of the token submitted for introspection.
     */
    @SuppressWarnings("MethodName")
    public void setToken_type_hint(@Nullable String tokenTypeHint) {
        this.token_type_hint = tokenTypeHint;
    }

    @Override
    public String toString() {
        return "IntrospectionRequest{" +
                "token='" + token + '\'' +
                ", token_type_hint='" + token_type_hint + '\'' +
                '}';
    }
}
