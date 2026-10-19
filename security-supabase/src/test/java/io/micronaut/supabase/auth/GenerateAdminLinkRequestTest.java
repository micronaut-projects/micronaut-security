package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.GenerateAdminLinkRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link GenerateAdminLinkRequest}.
 */
@MicronautTest(startApplication = false)
class GenerateAdminLinkRequestTest {

    private static final GenerateAdminLinkRequest SAMPLE = new GenerateAdminLinkRequest(
        "magiclink",
        "alice@example.com",
        "alice.new@example.com",
        "correct-horse-battery",
        Map.of("display_name", "Alice"),
        "http://localhost:3000/welcome"
    );

    private static final String JSON = """
        {"type":"magiclink","email":"alice@example.com","new_email":"alice.new@example.com","password":"correct-horse-battery","data":{"display_name":"Alice"},"redirect_to":"http://localhost:3000/welcome"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeGenerateAdminLinkRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(GenerateAdminLinkRequest.class));
    }

    @Test
    void typeGenerateAdminLinkRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(GenerateAdminLinkRequest.class)));
    }

    @Test
    void typeGenerateAdminLinkRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(GenerateAdminLinkRequest.class)));
    }

    @Test
    void generateAdminLinkRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void generateAdminLinkRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(GenerateAdminLinkRequest.class)));
    }

    @Test
    void generateAdminLinkRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"newEmail", "password", "data", "redirectTo"})
    void typeGenerateAdminLinkRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type", "email"})
    void typeGenerateAdminLinkRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type", "email"})
    void typeGenerateAdminLinkRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
