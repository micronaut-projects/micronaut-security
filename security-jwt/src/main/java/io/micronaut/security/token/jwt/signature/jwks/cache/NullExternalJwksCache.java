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
package io.micronaut.security.token.jwt.signature.jwks.cache;

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.security.token.jwt.signature.jwks.cache.ExternalJwksCache;
import java.util.List;

public class NullExternalJwksCache implements ExternalJwksCache {

    @Override
    public JWKSet get(String url) {
        return null;
    }

    @Override
    public boolean isPresent(String url) {
        return false;
    }

    @Override
    public void clear(String url) {

    }

    @Override
    public List<String> getKeyIds(String url) {
        return null;
    }

    @Override
    public void setJWKSet(String url,JWKSet jwkSet) {

    }
}
