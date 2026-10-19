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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CopyObjectRequest}.
 */
@MicronautTest(startApplication = false)
class CopyObjectRequestTest {

    private static final CopyObjectRequest SAMPLE = new CopyObjectRequest("avatars", "folder/alice.png", "47e4196f-8cf4-496d-abee-29ff89848cd2", "archive", "2026/alice.png", new CopyObjectRequest.Metadata("max-age=3600", "gzip", "image/png"), true);

    private static final String JSON = """
        {"bucketId":"avatars","sourceKey":"folder/alice.png","sourceVersionId":"47e4196f-8cf4-496d-abee-29ff89848cd2","destinationBucket":"archive","destinationKey":"2026/alice.png","metadata":{"cacheControl":"max-age=3600","contentEncoding":"gzip","mimetype":"image/png"},"copyMetadata":true}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCopyObjectRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CopyObjectRequest.class));
    }

    @Test
    void typeCopyObjectRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CopyObjectRequest.class)));
    }

    @Test
    void typeCopyObjectRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CopyObjectRequest.class)));
    }

    @Test
    void copyObjectRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void copyObjectRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CopyObjectRequest.class)));
    }

    @Test
    void copyObjectRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"sourceVersionId", "destinationBucket", "metadata", "copyMetadata"})
    void typeCopyObjectRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bucketId", "sourceKey", "destinationKey"})
    void typeCopyObjectRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bucketId", "sourceKey", "destinationKey"})
    void typeCopyObjectRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
