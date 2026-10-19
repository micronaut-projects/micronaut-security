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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SignObjectsRequest}.
 */
@MicronautTest(startApplication = false)
class SignObjectsRequestTest {

    private static final SignObjectsRequest SAMPLE = new SignObjectsRequest(60, List.of("folder/alice.png", "folder/bob.png"));

    private static final String JSON = """
        {"expiresIn":60,"paths":["folder/alice.png","folder/bob.png"]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSignObjectsRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SignObjectsRequest.class));
    }

    @Test
    void typeSignObjectsRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SignObjectsRequest.class)));
    }

    @Test
    void typeSignObjectsRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SignObjectsRequest.class)));
    }

    @Test
    void signObjectsRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void signObjectsRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SignObjectsRequest.class)));
    }

    @Test
    void signObjectsRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"expiresIn", "paths"})
    void typeSignObjectsRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @Test
    void expiresInMustBePositiveAndPathsCannotBeEmpty() {
        assertFalse(validator.validate(Records.with(SAMPLE, "expiresIn", 0)).isEmpty());
        assertFalse(validator.validate(Records.with(SAMPLE, "paths", List.of())).isEmpty());
    }
}
