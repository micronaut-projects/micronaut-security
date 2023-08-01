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

import io.lettuce.core.api.StatefulRedisConnection;
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.signature.jwks.cache.dynamodb.DynamoDbJwksCache;
import io.micronaut.security.token.jwt.signature.jwks.cache.redis.RedisJwksCache;
import io.micronaut.serde.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@Factory
public class ExternalJwksCacheFactory {

    private static final Logger log = LoggerFactory.getLogger(ExternalJwksCacheFactory.class);

    private final ExternalJwksCacheConfiguration externalJwksCacheConfiguration;
    private final StatefulRedisConnection<String, String> redisConnection;

    public ExternalJwksCacheFactory(ExternalJwksCacheConfiguration externalJwksCacheConfiguration, @Nullable StatefulRedisConnection<String, String> redisConnection) {
        this.externalJwksCacheConfiguration = externalJwksCacheConfiguration;
        this.redisConnection = redisConnection;
    }

    @Bean
    public ExternalJwksCache getExternalJwksCache() {
        log.debug("Creating external JWKS cache...");
        if (externalJwksCacheConfiguration.isEnabled()) {
            return switch (externalJwksCacheConfiguration.getCacheType()) {
                case REDIS -> createRedisCache();
                case DYNAMODB -> createDynamoDbCache();
            };
        }
        return new NullExternalJwksCache();
    }

    private RedisJwksCache createRedisCache() {
        return new RedisJwksCache(redisConnection,
            externalJwksCacheConfiguration.getRedisCacheConfiguration(), ObjectMapper.getDefault());
    }

    private DynamoDbJwksCache createDynamoDbCache() {
        DynamoDbClient dynamoDbClient = DynamoDbClient.create();
        return new DynamoDbJwksCache(externalJwksCacheConfiguration.getDynamoDbCacheConfiguration(), dynamoDbClient, ObjectMapper.getDefault());
    }
}
