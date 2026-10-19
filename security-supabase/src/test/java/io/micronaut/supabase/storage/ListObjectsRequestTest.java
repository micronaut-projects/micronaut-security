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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link ListObjectsRequest}.
 */
@MicronautTest(startApplication = false)
class ListObjectsRequestTest {

    private static final ListObjectsRequest SAMPLE = new ListObjectsRequest("folder", false, 100, 0, new ListObjectsRequest.SortBy("name", "asc"), "alice", "include", "exclude");

    private static final String JSON = """
        {"prefix":"folder","exactMatch":false,"limit":100,"offset":0,"sortBy":{"column":"name","order":"asc"},"search":"alice","noncurrentVersions":"include","deleteMarkers":"exclude"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeListObjectsRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(ListObjectsRequest.class));
    }

    @Test
    void typeListObjectsRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(ListObjectsRequest.class)));
    }

    @Test
    void typeListObjectsRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(ListObjectsRequest.class)));
    }

    @Test
    void listObjectsRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void listObjectsRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(ListObjectsRequest.class)));
    }

    @Test
    void listObjectsRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"exactMatch", "limit", "offset", "sortBy", "search", "noncurrentVersions", "deleteMarkers"})
    void typeListObjectsRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"prefix"})
    void typeListObjectsRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @Test
    void prefixMayBeEmptyForTheBucketRoot() {
        assertTrue(validator.validate(Records.with(SAMPLE, "prefix", "")).isEmpty());
    }

    @Test
    void sortByColumnCannotBeBlank() {
        assertTrue(validator.validate(new ListObjectsRequest.SortBy("name", null)).isEmpty());
        assertFalse(validator.validate(new ListObjectsRequest.SortBy("", "asc")).isEmpty());
    }
}
