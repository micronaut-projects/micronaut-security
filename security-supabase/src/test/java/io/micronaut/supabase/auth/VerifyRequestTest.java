package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.VerifyRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link VerifyRequest}.
 */
@MicronautTest(startApplication = false)
class VerifyRequestTest {

    private static final VerifyRequest SAMPLE = new VerifyRequest(
        "magiclink",
        "123456",
        "token-hash",
        "alice@example.com",
        "+15555550100",
        "http://localhost:3000/welcome"
    );

    private static final String JSON = """
        {"type":"magiclink","token":"123456","token_hash":"token-hash","email":"alice@example.com","phone":"+15555550100","redirect_to":"http://localhost:3000/welcome"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeVerifyRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(VerifyRequest.class));
    }

    @Test
    void typeVerifyRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(VerifyRequest.class)));
    }

    @Test
    void typeVerifyRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(VerifyRequest.class)));
    }

    @Test
    void verifyRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void verifyRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(VerifyRequest.class)));
    }

    @Test
    void verifyRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "type",
        "token",
        "tokenHash",
        "email",
        "phone",
        "redirectTo"
    })
    void typeVerifyRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
