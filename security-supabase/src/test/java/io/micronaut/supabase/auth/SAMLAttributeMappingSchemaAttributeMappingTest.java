package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SAMLAttributeMappingSchema.AttributeMapping}.
 */
@MicronautTest(startApplication = false)
class SAMLAttributeMappingSchemaAttributeMappingTest {

    private static final SAMLAttributeMappingSchema.AttributeMapping SAMPLE = new SAMLAttributeMappingSchema.AttributeMapping("mail", List.of("mail", "email"), "guest");

    private static final String JSON = """
        {"name":"mail","names":["mail","email"],"default":"guest"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeAttributeMappingIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SAMLAttributeMappingSchema.AttributeMapping.class));
    }

    @Test
    void typeAttributeMappingIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SAMLAttributeMappingSchema.AttributeMapping.class)));
    }

    @Test
    void typeAttributeMappingIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SAMLAttributeMappingSchema.AttributeMapping.class)));
    }

    @Test
    void attributeMappingJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void attributeMappingJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SAMLAttributeMappingSchema.AttributeMapping.class)));
    }

    @Test
    void attributeMappingSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"name", "names", "defaultValue"})
    void typeAttributeMappingFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
