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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SignObjectRequest}.
 */
@MicronautTest(startApplication = false)
class SignObjectRequestTest {

    private static final SignObjectRequest SAMPLE = new SignObjectRequest(60, new TransformOptions(100, 200, "cover", "webp", 80, "fp", 0.5, 0.25), "47e4196f-8cf4-496d-abee-29ff89848cd2");

    private static final String JSON = """
        {"expiresIn":60,"transform":{"height":100,"width":200,"resize":"cover","format":"webp","quality":80,"gravity":"fp","x_offset":0.5,"y_offset":0.25},"versionId":"47e4196f-8cf4-496d-abee-29ff89848cd2"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSignObjectRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SignObjectRequest.class));
    }

    @Test
    void typeSignObjectRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SignObjectRequest.class)));
    }

    @Test
    void typeSignObjectRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SignObjectRequest.class)));
    }

    @Test
    void signObjectRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void signObjectRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SignObjectRequest.class)));
    }

    @Test
    void signObjectRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"transform", "versionId"})
    void typeSignObjectRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"expiresIn"})
    void typeSignObjectRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @Test
    void expiresInMustBePositive() {
        assertFalse(validator.validate(Records.with(SAMPLE, "expiresIn", 0)).isEmpty());
        assertFalse(validator.validate(Records.with(SAMPLE, "expiresIn", -1)).isEmpty());
    }
}
