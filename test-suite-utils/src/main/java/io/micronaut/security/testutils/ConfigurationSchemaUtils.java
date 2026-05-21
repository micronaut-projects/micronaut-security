/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.testutils;

import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.Assertions;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Utilities to assert generated Micronaut configuration schemas.
 */
public final class ConfigurationSchemaUtils {
    private static final String SCHEMA_DIRECTORY = "META-INF/micronaut-configuration-schemas/";
    private static final JsonMapper JSON_MAPPER = JsonMapper.createDefault();

    private ConfigurationSchemaUtils() {
    }

    public static void assertDefaults(String type, Map<String, Object> expected) throws IOException {
        Map<String, Object> properties = properties(type);
        for (Map.Entry<String, Object> entry : expected.entrySet()) {
            Map<String, Object> property = map(properties, entry.getKey());
            Assertions.assertEquals(entry.getValue(), property.get("default"), type + "." + entry.getKey());
        }
    }

    public static void assertSchemaMetadata(Map<String, Object> schema,
                                            String type,
                                            String prefix,
                                            String kind) {
        Assertions.assertEquals("https://json-schema.org/draft/2020-12/schema", schema.get("$schema"));
        Assertions.assertEquals("urn:micronaut:config:" + type, schema.get("$id"));
        Assertions.assertEquals(type, schema.get("title"));

        Map<String, Object> micronaut = map(schema, "x-micronaut");
        Assertions.assertEquals(prefix, micronaut.get("prefix"));
        Assertions.assertEquals(type, micronaut.get("type"));
        Assertions.assertEquals(kind, micronaut.get("kind"));
    }

    public static void assertProperty(Map<String, Object> properties,
                                      String name,
                                      String type,
                                      String javaType,
                                      Object defaultValue,
                                      String sourceType,
                                      String prefix) {
        Map<String, Object> property = map(properties, name);
        Assertions.assertEquals(type, property.get("type"));
        Assertions.assertEquals(defaultValue, property.get("default"));
        Assertions.assertEquals(javaType, property.get("x-micronaut-javaType"));
        Assertions.assertEquals(sourceType, property.get("x-micronaut-sourceType"));
        Assertions.assertEquals(prefix + "." + name, property.get("x-micronaut-path"));
    }

    public static Map<String, Object> properties(String type) throws IOException {
        Map<String, Object> schema = schema(type);
        if (schema.containsKey("properties")) {
            return map(schema, "properties");
        }
        return map(map(map(schema, "$defs"), "Entry"), "properties");
    }

    public static Map<String, Object> schema(String type) throws IOException {
        String path = SCHEMA_DIRECTORY + type + ".json";
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = ConfigurationSchemaUtils.class.getClassLoader();
        }
        InputStream inputStream = classLoader.getResourceAsStream(path);
        Assertions.assertNotNull(inputStream, () -> "Expected generated configuration schema " + path);
        try (inputStream) {
            return JSON_MAPPER.readValue(inputStream.readAllBytes(), Argument.mapOf(String.class, Object.class));
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Map<String, Object> source, String property) {
        return (Map<String, Object>) Assertions.assertInstanceOf(Map.class, source.get(property),
            () -> "Expected " + property + " to be a JSON object");
    }
}
