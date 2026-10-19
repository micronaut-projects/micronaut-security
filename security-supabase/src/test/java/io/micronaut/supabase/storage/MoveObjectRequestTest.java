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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link MoveObjectRequest}.
 */
@MicronautTest(startApplication = false)
class MoveObjectRequestTest {

    private static final MoveObjectRequest SAMPLE = new MoveObjectRequest("avatars", "folder/alice.png", "47e4196f-8cf4-496d-abee-29ff89848cd2", "archive", "2026/alice.png");

    private static final String JSON = """
        {"bucketId":"avatars","sourceKey":"folder/alice.png","sourceVersionId":"47e4196f-8cf4-496d-abee-29ff89848cd2","destinationBucket":"archive","destinationKey":"2026/alice.png"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeMoveObjectRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(MoveObjectRequest.class));
    }

    @Test
    void typeMoveObjectRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(MoveObjectRequest.class)));
    }

    @Test
    void typeMoveObjectRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(MoveObjectRequest.class)));
    }

    @Test
    void moveObjectRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void moveObjectRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(MoveObjectRequest.class)));
    }

    @Test
    void moveObjectRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"sourceVersionId", "destinationBucket"})
    void typeMoveObjectRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bucketId", "sourceKey", "destinationKey"})
    void typeMoveObjectRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bucketId", "sourceKey", "destinationKey"})
    void typeMoveObjectRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
