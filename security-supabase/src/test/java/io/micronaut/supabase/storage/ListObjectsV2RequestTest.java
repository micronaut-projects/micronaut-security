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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ListObjectsV2Request}.
 */
@MicronautTest(startApplication = false)
class ListObjectsV2RequestTest {

    private static final ListObjectsV2Request SAMPLE = new ListObjectsV2Request("folder/", false, 100, "cursor-fixture", true, new ListObjectsRequest.SortBy("name", "asc"), "include", "exclude");

    private static final String JSON = """
        {"prefix":"folder/","exactMatch":false,"limit":100,"cursor":"cursor-fixture","with_delimiter":true,"sortBy":{"column":"name","order":"asc"},"noncurrentVersions":"include","deleteMarkers":"exclude"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeListObjectsV2RequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ListObjectsV2Request.class));
    }

    @Test
    void typeListObjectsV2RequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ListObjectsV2Request.class)));
    }

    @Test
    void typeListObjectsV2RequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ListObjectsV2Request.class)));
    }

    @Test
    void listObjectsV2RequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void listObjectsV2RequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ListObjectsV2Request.class)));
    }

    @Test
    void listObjectsV2RequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"prefix", "exactMatch", "limit", "cursor", "withDelimiter", "sortBy", "noncurrentVersions", "deleteMarkers"})
    void typeListObjectsV2RequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
