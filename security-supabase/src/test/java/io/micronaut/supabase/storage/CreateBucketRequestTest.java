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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CreateBucketRequest}.
 */
@MicronautTest(startApplication = false)
class CreateBucketRequestTest {

    private static final CreateBucketRequest SAMPLE = new CreateBucketRequest("avatars", "avatars", true, "STANDARD", "DISABLED", 1048576, List.of("image/png"));

    private static final String JSON = """
        {"name":"avatars","id":"avatars","public":true,"type":"STANDARD","versioning_status":"DISABLED","file_size_limit":1048576,"allowed_mime_types":["image/png"]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCreateBucketRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CreateBucketRequest.class));
    }

    @Test
    void typeCreateBucketRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CreateBucketRequest.class)));
    }

    @Test
    void typeCreateBucketRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CreateBucketRequest.class)));
    }

    @Test
    void createBucketRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void createBucketRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CreateBucketRequest.class)));
    }

    @Test
    void createBucketRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "isPublic", "type", "versioningStatus", "fileSizeLimit", "allowedMimeTypes"})
    void typeCreateBucketRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeCreateBucketRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeCreateBucketRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @Test
    void fileSizeLimitMayBeAStringWithAUnit() throws IOException {
        CreateBucketRequest request = new CreateBucketRequest("avatars", null, null, null, null, "10MB", null);

        assertEquals("""
            {"name":"avatars","file_size_limit":"10MB"}""", jsonMapper.writeValueAsString(request));
    }
}
