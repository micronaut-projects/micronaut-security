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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link DeleteObjectsRequest}.
 */
@MicronautTest(startApplication = false)
class DeleteObjectsRequestTest {

    private static final DeleteObjectsRequest SAMPLE = new DeleteObjectsRequest(List.of("folder/alice.png", "folder/bob.png"));

    private static final String JSON = """
        {"prefixes":["folder/alice.png","folder/bob.png"]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeDeleteObjectsRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(DeleteObjectsRequest.class));
    }

    @Test
    void typeDeleteObjectsRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(DeleteObjectsRequest.class)));
    }

    @Test
    void typeDeleteObjectsRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(DeleteObjectsRequest.class)));
    }

    @Test
    void deleteObjectsRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void deleteObjectsRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(DeleteObjectsRequest.class)));
    }

    @Test
    void deleteObjectsRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"prefixes"})
    void typeDeleteObjectsRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @Test
    void prefixesCannotBeEmpty() {
        assertFalse(validator.validate(new DeleteObjectsRequest(List.of())).isEmpty());
    }
}
