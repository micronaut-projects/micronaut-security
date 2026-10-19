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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ListObjectsV2Response}.
 */
@MicronautTest(startApplication = false)
class ListObjectsV2ResponseTest {

    private static final ListObjectsV2Response SAMPLE = new ListObjectsV2Response(List.of(), List.of(new ObjectSchema("alice.png", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", "47e4196f-8cf4-496d-abee-29ff89848cd2", "9b5ebd1d-786e-4d8a-857c-31427a82fb09", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", Map.of("size", 11), Map.of("owner", "alice"), "2026-10-19T04:28:26.494Z", false, true, "folder/alice.png", new BucketSchema("avatars", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", true, "STANDARD", "DISABLED", 1048576L, List.of("image/png"), "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z"))), true, "cursor-fixture", "folder/alice.png");

    private static final String JSON = """
        {"folders":[],"objects":[{"name":"alice.png","bucket_id":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","version":"47e4196f-8cf4-496d-abee-29ff89848cd2","id":"9b5ebd1d-786e-4d8a-857c-31427a82fb09","updated_at":"2026-10-19T04:28:26.494Z","created_at":"2026-10-19T04:28:26.494Z","last_accessed_at":"2026-10-19T04:28:26.494Z","metadata":{"size":11},"user_metadata":{"owner":"alice"},"archived_at":"2026-10-19T04:28:26.494Z","is_delete_marker":false,"is_versioned":true,"key":"folder/alice.png","buckets":{"id":"avatars","name":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","public":true,"type":"STANDARD","versioning_status":"DISABLED","file_size_limit":1048576,"allowed_mime_types":["image/png"],"created_at":"2026-10-19T04:28:26.494Z","updated_at":"2026-10-19T04:28:26.494Z"}}],"hasNext":true,"nextCursor":"cursor-fixture","nextCursorKey":"folder/alice.png"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeListObjectsV2ResponseIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ListObjectsV2Response.class));
    }

    @Test
    void typeListObjectsV2ResponseIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ListObjectsV2Response.class)));
    }

    @Test
    void typeListObjectsV2ResponseIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ListObjectsV2Response.class)));
    }

    @Test
    void listObjectsV2ResponseJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void listObjectsV2ResponseJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ListObjectsV2Response.class)));
    }

    @Test
    void listObjectsV2ResponseSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"nextCursor", "nextCursorKey"})
    void typeListObjectsV2ResponseFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"folders", "objects", "hasNext"})
    void typeListObjectsV2ResponseFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
