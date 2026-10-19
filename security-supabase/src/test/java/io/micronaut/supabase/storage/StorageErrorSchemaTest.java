package io.micronaut.supabase.storage;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.Records;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link StorageErrorSchema}.
 */
@MicronautTest(startApplication = false)
class StorageErrorSchemaTest {

    private static final StorageErrorSchema SAMPLE = new StorageErrorSchema("404", "not_found", "Object not found", "NoSuchKey");

    private static final String JSON = """
        {"statusCode":"404","error":"not_found","message":"Object not found","code":"NoSuchKey"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeStorageErrorSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(StorageErrorSchema.class));
    }

    @Test
    void typeStorageErrorSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(StorageErrorSchema.class)));
    }

    @Test
    void typeStorageErrorSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(StorageErrorSchema.class)));
    }

    @Test
    void storageErrorSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void storageErrorSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(StorageErrorSchema.class)));
    }

    @Test
    void storageErrorSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"statusCode", "error", "message", "code"})
    void typeStorageErrorSchemaFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"statusCode", "error", "message", "code"})
    void typeStorageErrorSchemaFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
