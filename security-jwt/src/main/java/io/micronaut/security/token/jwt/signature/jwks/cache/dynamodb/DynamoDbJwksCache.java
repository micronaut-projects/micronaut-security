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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.security.token.jwt.signature.jwks.cache.ExternalJwksCache;
import io.micronaut.serde.ObjectMapper;
import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

public class DynamoDbJwksCache implements ExternalJwksCache {

    private static final String JWKSET_KEY = "JWKSET";
    private final DynamoDbCacheConfiguration dynamoDbCacheConfiguration;
    private final DynamoDbClient dynamoDbClient;
    private final ObjectMapper objectMapper;

    public DynamoDbJwksCache(DynamoDbCacheConfiguration dynamoDbCacheConfiguration,
        DynamoDbClient dynamoDbClient, ObjectMapper objectMapper) {
        this.dynamoDbCacheConfiguration = dynamoDbCacheConfiguration;
        this.dynamoDbClient = dynamoDbClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public JWKSet get(String url) {
        GetItemRequest request = GetItemRequest.builder()
            .tableName(dynamoDbCacheConfiguration.getTableName())
            .key(Map.of(dynamoDbCacheConfiguration.getPrimaryKey(), AttributeValue.fromS(url),
                dynamoDbCacheConfiguration.getSecondaryKey(), AttributeValue.fromS(url))).build();
        AttributeValue attributeValue = dynamoDbClient.getItem(request).item().get(JWKSET_KEY);
        try {
            if (attributeValue == null || attributeValue.s() == null) {
                return null;
            }
            return JWKSet.parse(attributeValue.s());
        } catch (ParseException e) {
            return null;
        }
    }

    @Override
    public boolean isPresent(String url) {
        return get(url) != null;
    }

    @Override
    public void clear(String url) {
        DeleteItemRequest deleteItemRequest = DeleteItemRequest.builder()
            .tableName(dynamoDbCacheConfiguration.getTableName())
            .key(Map.of(dynamoDbCacheConfiguration.getPrimaryKey(), AttributeValue.fromS(url),
                dynamoDbCacheConfiguration.getSecondaryKey(), AttributeValue.fromS(url))).build();
        dynamoDbClient.deleteItem(deleteItemRequest);
    }

    @Override
    public List<String> getKeyIds(String url) {
        return get(url).getKeys().stream().map(JWK::getKeyID).collect(Collectors.toList());
    }

    @Override
    public void setJWKSet(String url, JWKSet jwkSet) {
        try {
            PutItemRequest putItemRequest = PutItemRequest.builder().tableName(
                dynamoDbCacheConfiguration.getTableName()).item(Map.of(
                dynamoDbCacheConfiguration.getPrimaryKey(), AttributeValue.fromS(url),
                dynamoDbCacheConfiguration.getSecondaryKey(), AttributeValue.fromS(url),
                dynamoDbCacheConfiguration.getTtlKey(), AttributeValue.fromN(String.valueOf(
                    Instant.now().getEpochSecond() + dynamoDbCacheConfiguration.getTtl())),
                JWKSET_KEY, AttributeValue.fromS(
                    objectMapper.writeValueAsString(jwkSet.toJSONObject())))).build();
            dynamoDbClient.putItem(putItemRequest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
