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
import io.micronaut.security.oauth2.grants.AsMap;
import io.reactivex.annotations.NonNull;
import io.reactivex.annotations.Nullable;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

/**
 * Introspection Request.
 * @see <a href="https://tools.ietf.org/html/rfc7662#section-2.1">Introspection Request</a>.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Introspected
public class IntrospectionRequest implements AsMap {

    public static final String KEY_TOKEN = "token";
    public static final String KEY_TOKENTYPEHINT = "token_type_hint";

    @NonNull
    @NotNull
    private String token;

    @JsonProperty(KEY_TOKENTYPEHINT)
    @Nullable
    private String tokenTypeHint;

    /**
     * Constructor.
     */
    public IntrospectionRequest() {

    }

    /**
     *
     * @param token The string value of the token.
     */
    public IntrospectionRequest(@NonNull String token) {
        this.token = token;
    }

    /**
     *
     * @param token  The string value of the token.
     * @param tokenTypeHint  A hint about the type of the token submitted for
     *       introspection.
     */
    public IntrospectionRequest(@NonNull String token, @Nullable String tokenTypeHint) {
        this.token = token;
        this.tokenTypeHint = tokenTypeHint;
    }

    /**
     *
     * @return  The string value of the token.
     */
    public String getToken() {
        return token;
    }

    /**
     *
     * @param token  The string value of the token.
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     *
     * @return A hint about the type of the token submitted for
     *       introspection.
     */
    public String getTokenTypeHint() {
        return tokenTypeHint;
    }

    /**
     *
     * @param tokenTypeHint A hint about the type of the token submitted for
     *       introspection.
     */
    public void setTokenTypeHint(String tokenTypeHint) {
        this.tokenTypeHint = tokenTypeHint;
    }

    @Override
    public Map<String, String> toMap() {
        Map<String, String> m = new HashMap<>(getTokenTypeHint() != null ? 2 : 1);
        m.put(KEY_TOKEN, getToken());
        if (getTokenTypeHint() != null) {
            m.put(KEY_TOKENTYPEHINT, getTokenTypeHint());
        }
        return m;
    }
}

