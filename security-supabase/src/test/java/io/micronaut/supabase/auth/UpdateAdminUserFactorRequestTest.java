package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateAdminUserFactorRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link UpdateAdminUserFactorRequest}.
 */
@MicronautTest(startApplication = false)
class UpdateAdminUserFactorRequestTest {

    private static final UpdateAdminUserFactorRequest SAMPLE = new UpdateAdminUserFactorRequest();

    private static final String JSON = """
        {}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeUpdateAdminUserFactorRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(UpdateAdminUserFactorRequest.class));
    }

    @Test
    void typeUpdateAdminUserFactorRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(UpdateAdminUserFactorRequest.class)));
    }

    @Test
    void typeUpdateAdminUserFactorRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(UpdateAdminUserFactorRequest.class)));
    }

    @Test
    void updateAdminUserFactorRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void updateAdminUserFactorRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(UpdateAdminUserFactorRequest.class)));
    }

    @Test
    void updateAdminUserFactorRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }
}
