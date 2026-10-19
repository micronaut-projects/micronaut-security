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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link BucketSchema}.
 */
@MicronautTest(startApplication = false)
class BucketSchemaTest {

    private static final BucketSchema SAMPLE = new BucketSchema("avatars", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", true, "STANDARD", "DISABLED", 1048576L, List.of("image/png"), "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z");

    private static final String JSON = """
        {"id":"avatars","name":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","public":true,"type":"STANDARD","versioning_status":"DISABLED","file_size_limit":1048576,"allowed_mime_types":["image/png"],"created_at":"2026-10-19T04:28:26.494Z","updated_at":"2026-10-19T04:28:26.494Z"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeBucketSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(BucketSchema.class));
    }

    @Test
    void typeBucketSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(BucketSchema.class)));
    }

    @Test
    void typeBucketSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(BucketSchema.class)));
    }

    @Test
    void bucketSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void bucketSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(BucketSchema.class)));
    }

    @Test
    void bucketSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"owner", "ownerId", "isPublic", "type", "versioningStatus", "fileSizeLimit", "allowedMimeTypes", "createdAt", "updatedAt"})
    void typeBucketSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "name"})
    void typeBucketSchemaFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "name"})
    void typeBucketSchemaFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
