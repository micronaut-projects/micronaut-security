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

import org.jspecify.annotations.Nullable;

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
     * The key of the client assertion in the token request body.
     * @since 5.5.3
     */
    String KEY_CLIENT_ASSERTION = "client_assertion";

    /**
     * The key of the client assertion type in the token request body.
     * @since 5.5.3
     */
    String KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";

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

    /**
     * Sets the client assertion (signed JWT) used for {@code private_key_jwt} client authentication.
     *
     * @param clientAssertion The signed JWT assertion
     * @since 5.5.3
     */
    default void setClientAssertion(@Nullable String clientAssertion) {
        // no-op for backward compatibility
    }

    /**
     * Sets the client assertion type, typically {@code urn:ietf:params:oauth:client-assertion-type:jwt-bearer}.
     *
     * @param clientAssertionType The assertion type URI
     * @since 5.5.3
     */
    default void setClientAssertionType(@Nullable String clientAssertionType) {
        // no-op for backward compatibility
    }
}
