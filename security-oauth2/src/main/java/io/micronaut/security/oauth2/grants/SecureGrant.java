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

/**
 * A contract for a grant that requires authentication.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface SecureGrant {

    String KEY_CLIENT_ID = "client_id";
    String KEY_CLIENT_SECRET = "client_secret";

    /**
     * Sets the client id in the grant.
     *
     * @param clientId The client id
     */
    void setClientId(String clientId);

    /**
     * Sets the client secret in the grant.
     *
     * @param clientSecret The client secret
     */
    void setClientSecret(String clientSecret);
}
