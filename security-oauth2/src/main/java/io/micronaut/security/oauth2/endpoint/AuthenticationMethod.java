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
package io.micronaut.security.oauth2.endpoint;

/**
 * Client Authentication methods that are used by Clients to authenticate to the Authorization Server when using the Token Endpoint.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-campbell-oauth-mtls">Mutual TLS Profiles for OAuth Clients</a>
 * @author Sergio del Amo
 * @since 1.2.0
 */
public enum AuthenticationMethod {

    CLIENT_SECRET_POST("client_secret_post"),
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY_JWT("private_key_jwt"),
    TLS_CLIENT_AUTH("tls_client_auth"),
    NONE("none");

    private String authMethod;

    /**
     *
     * @param authMethod Authentication method.
     */
    AuthenticationMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    /**
     *
     * @return The authentication method.
     */
    @Override
    public String toString() {
        return authMethod;
    }
}
