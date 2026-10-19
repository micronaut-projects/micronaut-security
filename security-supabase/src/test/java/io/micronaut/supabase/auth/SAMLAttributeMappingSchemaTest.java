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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SAMLAttributeMappingSchema}.
 */
@MicronautTest(startApplication = false)
class SAMLAttributeMappingSchemaTest {

    private static final SAMLAttributeMappingSchema SAMPLE = new SAMLAttributeMappingSchema(
        Map.of("email", new SAMLAttributeMappingSchema.AttributeMapping("mail", List.of("mail", "email"), "guest"))
    );

    private static final String JSON = """
        {"keys":{"email":{"name":"mail","names":["mail","email"],"default":"guest"}}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSAMLAttributeMappingSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SAMLAttributeMappingSchema.class));
    }

    @Test
    void typeSAMLAttributeMappingSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SAMLAttributeMappingSchema.class)));
    }

    @Test
    void typeSAMLAttributeMappingSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SAMLAttributeMappingSchema.class)));
    }

    @Test
    void samlAttributeMappingSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void samlAttributeMappingSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SAMLAttributeMappingSchema.class)));
    }

    @Test
    void samlAttributeMappingSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"keys"})
    void typeSAMLAttributeMappingSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
