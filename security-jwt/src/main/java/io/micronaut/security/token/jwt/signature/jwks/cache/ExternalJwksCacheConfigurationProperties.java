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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import io.micronaut.security.token.jwt.signature.jwks.cache.dynamodb.DynamoDbCacheConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.cache.redis.RedisCacheConfiguration;
import jakarta.inject.Inject;

@ConfigurationProperties(ExternalJwksCacheConfigurationProperties.PREFIX)
public class ExternalJwksCacheConfigurationProperties implements ExternalJwksCacheConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".signatures.cache";

    private ExternalJwksCacheType cacheType;
    private boolean enabled;
    @Inject
    @Nullable
    private DynamoDbCacheConfiguration dynamoDbCacheConfiguration;

    @Inject
    @Nullable
    private RedisCacheConfiguration redisCacheConfiguration;

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public ExternalJwksCacheType getCacheType() {
        return this.cacheType;
    }

    public void setCacheType(
        ExternalJwksCacheType cacheType) {
        this.cacheType = cacheType;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public DynamoDbCacheConfiguration getDynamoDbCacheConfiguration() {
        return dynamoDbCacheConfiguration;
    }

    public void setDynamoDbCacheConfiguration(
        DynamoDbCacheConfiguration dynamoDbCacheConfiguration) {
        this.dynamoDbCacheConfiguration = dynamoDbCacheConfiguration;
    }

    @Override
    public RedisCacheConfiguration getRedisCacheConfiguration() {
        return redisCacheConfiguration;
    }

    public void setRedisCacheConfiguration(
        RedisCacheConfiguration redisCacheConfiguration) {
        this.redisCacheConfiguration = redisCacheConfiguration;
    }
}
