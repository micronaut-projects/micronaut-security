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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ErrorSchema}.
 */
@MicronautTest(startApplication = false)
class ErrorSchemaTest {

    private static final ErrorSchema SAMPLE = new ErrorSchema(
        "invalid_request",
        "The request is missing a required parameter",
        400,
        "Invalid login credentials",
        "validation_failed",
        new ErrorSchema.WeakPassword(List.of("length"))
    );

    private static final String JSON = """
        {"error":"invalid_request","error_description":"The request is missing a required parameter","code":400,"msg":"Invalid login credentials","error_code":"validation_failed","weak_password":{"reasons":["length"]}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeErrorSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ErrorSchema.class));
    }

    @Test
    void typeErrorSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ErrorSchema.class)));
    }

    @Test
    void typeErrorSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ErrorSchema.class)));
    }

    @Test
    void errorSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void errorSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ErrorSchema.class)));
    }

    @Test
    void errorSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "error",
        "errorDescription",
        "code",
        "msg",
        "errorCode",
        "weakPassword"
    })
    void typeErrorSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
