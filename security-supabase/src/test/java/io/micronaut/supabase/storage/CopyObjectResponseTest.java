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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CopyObjectResponse}.
 */
@MicronautTest(startApplication = false)
class CopyObjectResponseTest {

    private static final CopyObjectResponse SAMPLE = new CopyObjectResponse("9b5ebd1d-786e-4d8a-857c-31427a82fb09", "avatars/2026/alice.png", "2026/alice.png", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", "47e4196f-8cf4-496d-abee-29ff89848cd2", "9b5ebd1d-786e-4d8a-857c-31427a82fb09", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z", Map.of("size", 11), Map.of("owner", "alice"), "2026-10-19T04:28:26.494Z", false, true, new BucketSchema("avatars", "avatars", "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", true, "STANDARD", "DISABLED", 1048576L, List.of("image/png"), "2026-10-19T04:28:26.494Z", "2026-10-19T04:28:26.494Z"));

    private static final String JSON = """
        {"Id":"9b5ebd1d-786e-4d8a-857c-31427a82fb09","Key":"avatars/2026/alice.png","name":"2026/alice.png","bucket_id":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","version":"47e4196f-8cf4-496d-abee-29ff89848cd2","id":"9b5ebd1d-786e-4d8a-857c-31427a82fb09","updated_at":"2026-10-19T04:28:26.494Z","created_at":"2026-10-19T04:28:26.494Z","last_accessed_at":"2026-10-19T04:28:26.494Z","metadata":{"size":11},"user_metadata":{"owner":"alice"},"archived_at":"2026-10-19T04:28:26.494Z","is_delete_marker":false,"is_versioned":true,"buckets":{"id":"avatars","name":"avatars","owner":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","owner_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","public":true,"type":"STANDARD","versioning_status":"DISABLED","file_size_limit":1048576,"allowed_mime_types":["image/png"],"created_at":"2026-10-19T04:28:26.494Z","updated_at":"2026-10-19T04:28:26.494Z"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCopyObjectResponseIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CopyObjectResponse.class));
    }

    @Test
    void typeCopyObjectResponseIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CopyObjectResponse.class)));
    }

    @Test
    void typeCopyObjectResponseIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CopyObjectResponse.class)));
    }

    @Test
    void copyObjectResponseJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void copyObjectResponseJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CopyObjectResponse.class)));
    }

    @Test
    void copyObjectResponseSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"objectId", "name", "bucketId", "owner", "ownerId", "version", "id", "updatedAt", "createdAt", "lastAccessedAt", "metadata", "userMetadata", "archivedAt", "isDeleteMarker", "isVersioned", "buckets"})
    void typeCopyObjectResponseFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"key"})
    void typeCopyObjectResponseFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"key"})
    void typeCopyObjectResponseFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
