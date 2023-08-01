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
package io.micronaut.security.token.jwt.signature.jwks.cache.dynamodb;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.token.jwt.signature.jwks.cache.ExternalJwksCacheConfigurationProperties;


@ConfigurationProperties(DynamoDbCacheConfigurationProperties.PREFIX)
public class DynamoDbCacheConfigurationProperties implements DynamoDbCacheConfiguration {

    public static final String PREFIX = ExternalJwksCacheConfigurationProperties.PREFIX + ".dynamodb";

    private static final String PRIMARY_KEY_DEFAULT = "PK";
    private static final String SECONDARY_KEY_DEFAULT = "SK";

    private static final String TTL_KEY_DEFAULT = "TTL";

    private static final Integer TTL_DEFAULT = 3600; // 1 hour

    private String tableName;
    private String primaryKey = PRIMARY_KEY_DEFAULT;

    private String secondaryKey = SECONDARY_KEY_DEFAULT;

    private String ttlKey = TTL_KEY_DEFAULT;

    private Integer ttl = TTL_DEFAULT;


    @Override
    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    @Override
    public String getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(String primaryKey) {
        this.primaryKey = primaryKey;
    }

    @Override
    public String getSecondaryKey() {
        return secondaryKey;
    }

    public void setSecondaryKey(String secondaryKey) {
        this.secondaryKey = secondaryKey;
    }

    @Override
    public Integer getTtl() {
        return ttl;
    }

    public void setTtl(Integer ttl) {
        this.ttl = ttl;
    }

    @Override
    public String getTtlKey() {
        return ttlKey;
    }

    public void setTtlKey(String ttlKey) {
        this.ttlKey = ttlKey;
    }
}
