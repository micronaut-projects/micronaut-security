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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ObjectSchema}.
 */
@MicronautTest(startApplication = false)
class ObjectSchemaTest {

    private static final ObjectSchema SAMPLE = new ObjectSchema("alice.png", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", "47e4196f-8cf4-496d-abee-29ff89848cd2", "9b5ebd1d-786e-4d8a-857c-31427a82fb09", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", Map.of("size", 11), Map.of("owner", "alice"), "2026-10-19T04:28:26.494Z", false, true, "folder/alice.png", new BucketSchema("avatars", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", true, "STANDARD", "DISABLED", 1048576L, List.of("image/png"), "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z"));

    private static final String JSON = """
        {"name":"alice.png","bucket_id":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","version":"47e4196f-8cf4-496d-abee-29ff89848cd2","id":"9b5ebd1d-786e-4d8a-857c-31427a82fb09","updated_at":"2026-10-19T04:28:26.494Z","created_at":"2026-10-19T04:28:26.494Z","last_accessed_at":"2026-10-19T04:28:26.494Z","metadata":{"size":11},"user_metadata":{"owner":"alice"},"archived_at":"2026-10-19T04:28:26.494Z","is_delete_marker":false,"is_versioned":true,"key":"folder/alice.png","buckets":{"id":"avatars","name":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","public":true,"type":"STANDARD","versioning_status":"DISABLED","file_size_limit":1048576,"allowed_mime_types":["image/png"],"created_at":"2026-10-19T04:28:26.494Z","updated_at":"2026-10-19T04:28:26.494Z"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeObjectSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ObjectSchema.class));
    }

    @Test
    void typeObjectSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ObjectSchema.class)));
    }

    @Test
    void typeObjectSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ObjectSchema.class)));
    }

    @Test
    void objectSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void objectSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ObjectSchema.class)));
    }

    @Test
    void objectSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"bucketId", "owner", "ownerId", "version", "id", "updatedAt", "createdAt", "lastAccessedAt", "metadata", "userMetadata", "archivedAt", "isDeleteMarker", "isVersioned", "key", "buckets"})
    void typeObjectSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeObjectSchemaFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeObjectSchemaFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
