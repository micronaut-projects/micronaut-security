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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ObjectInfoSchema}.
 */
@MicronautTest(startApplication = false)
class ObjectInfoSchemaTest {

    private static final ObjectInfoSchema SAMPLE = new ObjectInfoSchema("9b5ebd1d-786e-4d8a-857c-31427a82fb09", "folder/alice.png", "47e4196f-8cf4-496d-abee-29ff89848cd2", "avatars", 11L, "image/png", "max-age=3600", "gzip", "\"44997f87b891f89472b7f2bbe4e000c3\"", Map.of("owner", "alice"), "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", false, true);

    private static final String JSON = """
        {"id":"9b5ebd1d-786e-4d8a-857c-31427a82fb09","name":"folder/alice.png","version":"47e4196f-8cf4-496d-abee-29ff89848cd2","bucket_id":"avatars","size":11,"content_type":"image/png","cache_control":"max-age=3600","content_encoding":"gzip","etag":"\\"44997f87b891f89472b7f2bbe4e000c3\\"","metadata":{"owner":"alice"},"last_modified":"2026-10-19T04:28:26.494Z","created_at":"2026-10-19T04:28:26.494Z","archived_at":"2026-10-19T04:28:26.494Z","is_delete_marker":false,"is_versioned":true}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeObjectInfoSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ObjectInfoSchema.class));
    }

    @Test
    void typeObjectInfoSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ObjectInfoSchema.class)));
    }

    @Test
    void typeObjectInfoSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ObjectInfoSchema.class)));
    }

    @Test
    void objectInfoSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void objectInfoSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ObjectInfoSchema.class)));
    }

    @Test
    void objectInfoSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "name", "version", "bucketId", "size", "contentType", "cacheControl", "contentEncoding", "etag", "metadata", "lastModified", "createdAt", "archivedAt", "isDeleteMarker", "isVersioned"})
    void typeObjectInfoSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
