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
package io.micronaut.security.token.jwt.signature.jwks.cache.redis;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.lettuce.core.api.StatefulRedisConnection;
import io.micronaut.security.token.jwt.signature.jwks.cache.ExternalJwksCache;
import io.micronaut.serde.ObjectMapper;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;

public class RedisJwksCache implements ExternalJwksCache {

    private StatefulRedisConnection<String, String> redisConnection;

    private RedisCacheConfiguration redisCacheConfiguration;
    private ObjectMapper objectMapper;
    public RedisJwksCache(StatefulRedisConnection<String, String> redisConnection, RedisCacheConfiguration redisCacheConfiguration,
        ObjectMapper objectMapper) {
        this.redisConnection = redisConnection;
        this.redisCacheConfiguration = redisCacheConfiguration;
        this.objectMapper = objectMapper;
    }

    public JWKSet get(String url) {
        try {
            String jwksString = redisConnection.sync().get(url);
            if (jwksString == null) {
                return null;
            }
            return JWKSet.parse(jwksString);
        } catch (ParseException e) {
            return null;
        }
    }

    public boolean isPresent(String url) {
        return get(url) != null;
    }
    public void clear(String url)  {
        redisConnection.sync().del(url);
    }

    public List<String> getKeyIds(String url) {
        return get(url).getKeys().stream().map(JWK::getKeyID).toList();
    }

    @Override
    public void setJWKSet(String url, JWKSet jwkSet) {
        try {
            redisConnection.sync().set(url, objectMapper.writeValueAsString(jwkSet.toJSONObject()));
            redisConnection.sync().expire(url, redisCacheConfiguration.getTtl());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
