package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(startApplication = false)
class JacksonStateSerDesTest {

    @Inject JacksonStateSerDes serDes;

    @Test
    void testUrlSerialization() throws URISyntaxException {
        MutableState expected = new DefaultState();
        expected.setNonce("nonce");
        expected.setRedirectUri(new URI("https://example.com/path?query=param"));

        State deserialized = serDes.deserialize(serDes.serialize(expected));

        assertEquals(expected.getNonce(), deserialized.getNonce());
        assertEquals(expected.getRedirectUri(), deserialized.getRedirectUri());
    }

}
