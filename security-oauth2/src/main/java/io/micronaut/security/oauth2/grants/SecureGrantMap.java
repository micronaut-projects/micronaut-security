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

import java.util.HashMap;

/**
 * An implementation of {@link HashMap} that also implements {@link SecureGrant}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class SecureGrantMap extends HashMap<String, String> implements SecureGrant {

    /**
     * @param initialCapacity The initial capacity
     */
    public SecureGrantMap(int initialCapacity) {
        super(initialCapacity);
    }

    /**
     * Default constructor.
     */
    public SecureGrantMap() {
        super();
    }

    @Override
    public void setClientId(String clientId) {
        put("client_id", clientId);
    }

    @Override
    public void setClientSecret(String clientSecret) {
        put("client_secret", clientSecret);
    }
}
