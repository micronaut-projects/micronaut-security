package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.handlers.SignupHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignupControllerContentTypesForPostTest {
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private static final Map<String, String> BODY = Map.of("email", "alice@example.com", "password", "secret");

    @Test
    void formUrlEncodedBodyReachesTheSignupHandler() {
        assertBodyReachesTheSignupHandler(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    @Test
    void jsonBodyReachesTheSignupHandler() {
        assertBodyReachesTheSignupHandler(MediaType.APPLICATION_JSON_TYPE);
    }

    private static void assertBodyReachesTheSignupHandler(MediaType contentType) {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "SignupControllerContentTypesForPostTest"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<?> request = HttpRequest.POST("/signup", BODY).contentType(contentType);
            assertEquals(BODY, client.retrieve(request, MAP_ARGUMENT));
        }
    }

    @Requires(property = "spec.name", value = "SignupControllerContentTypesForPostTest")
    @Singleton
    static class EchoSignupHandler implements SignupHandler<HttpRequest<?>, HttpResponse<?>> {
        @Override
        public HttpResponse<?> signup(HttpRequest<?> request, Map<String, Object> body) {
            return HttpResponse.ok(body);
        }
    }
}
