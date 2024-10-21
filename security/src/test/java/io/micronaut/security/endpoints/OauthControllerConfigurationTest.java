package io.micronaut.security.endpoints;

import io.micronaut.http.MediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(startApplication = false)
class OauthControllerConfigurationTest {

    @Inject
    OauthControllerConfiguration oauthControllerConfiguration;

    @Test
    void defaultContentType() {
        assertEquals(Set.of(MediaType.APPLICATION_FORM_URLENCODED_TYPE, MediaType.APPLICATION_JSON_TYPE), oauthControllerConfiguration.getPostContentTypes());
    }
}