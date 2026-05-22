package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.NoSuchBeanException;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.security.handlers.ReactiveLogoutHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReactiveLogoutControllerTest {

    private static final String REACTIVE_SPEC = "ReactiveLogoutControllerTest";
    private static final String SYNC_SPEC = "SyncOnlyLogoutControllerTest";

    @Test
    void syncOnlyApplicationsUseLogoutController() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", SYNC_SPEC))) {
            assertInstanceOf(LogoutController.class, context.getBean(LogoutController.class));
            assertThrows(NoSuchBeanException.class, () -> context.getBean(ReactiveLogoutController.class));
        }
    }

    @Test
    void reactiveLogoutHandlerOwnsEndpointWhenBothHandlerTypesExist() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", REACTIVE_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            ApplicationContext context = server.getApplicationContext();
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap())
                .contentType(MediaType.APPLICATION_JSON_TYPE);

            HttpResponse<String> response = client.exchange(request, String.class);

            assertEquals("reactive", response.getBody().orElse(null));
            assertEquals("reactive", response.header("X-Logout-Handler"));
            assertEquals(1, context.getBean(ReactiveLogoutHandlerMock.class).invocations.get());
            assertEquals(0, context.getBean(SyncLogoutHandlerMock.class).invocations.get());
            assertInstanceOf(ReactiveLogoutController.class, context.getBean(ReactiveLogoutController.class));
            assertThrows(NoSuchBeanException.class, () -> context.getBean(LogoutController.class));
        }
    }

    @Test
    void reactiveLogoutWaitsForHandlerCompletion() throws Exception {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", REACTIVE_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            ReactiveLogoutHandlerMock handler = server.getApplicationContext().getBean(ReactiveLogoutHandlerMock.class);
            handler.response = new CompletableFuture<>();
            HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap())
                .contentType(MediaType.APPLICATION_JSON_TYPE);

            CompletableFuture<HttpResponse<String>> response = Mono.from(httpClient.exchange(request, String.class)).toFuture();

            assertTrue(handler.invoked.await(5, TimeUnit.SECONDS));
            assertFalse(response.isDone());

            handler.response.complete(HttpResponse.ok("complete").header("X-Logout-Handler", "reactive"));

            HttpResponse<String> httpResponse = response.get(5, TimeUnit.SECONDS);
            assertEquals(HttpStatus.OK, httpResponse.getStatus());
            assertEquals("complete", httpResponse.getBody().orElse(null));
        }
    }

    @Test
    void reactiveLogoutHonorsGetAllowedConfiguration() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", REACTIVE_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class, () -> client.exchange(HttpRequest.GET("/logout")));

            assertEquals(HttpStatus.METHOD_NOT_ALLOWED, exception.getStatus());
        }
    }

    @Test
    void reactiveLogoutHonorsPostContentTypes() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", REACTIVE_SPEC,
            "micronaut.security.endpoints.logout.post-content-types", Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED)
        ));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap())
                .contentType(MediaType.APPLICATION_JSON_TYPE);

            HttpClientResponseException exception = assertThrows(HttpClientResponseException.class, () -> client.exchange(request));

            assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
        }
    }

    @Requires(property = "spec.name", value = REACTIVE_SPEC)
    @Singleton
    static class ReactiveLogoutHandlerMock implements ReactiveLogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {
        private final AtomicInteger invocations = new AtomicInteger();
        private final CountDownLatch invoked = new CountDownLatch(1);
        private CompletableFuture<MutableHttpResponse<?>> response =
            CompletableFuture.completedFuture(HttpResponse.ok("reactive").header("X-Logout-Handler", "reactive"));

        @Override
        public Publisher<MutableHttpResponse<?>> logout(HttpRequest<?> request) {
            invocations.incrementAndGet();
            invoked.countDown();
            return Mono.fromFuture(response);
        }
    }

    @Requires(property = "spec.name", value = REACTIVE_SPEC)
    @Singleton
    static class SyncLogoutHandlerMock implements LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {
        private final AtomicInteger invocations = new AtomicInteger();

        @Override
        public MutableHttpResponse<?> logout(HttpRequest<?> request) {
            invocations.incrementAndGet();
            return HttpResponse.ok("sync").header("X-Logout-Handler", "sync");
        }
    }

    @Requires(property = "spec.name", value = SYNC_SPEC)
    @Singleton
    static class SyncOnlyLogoutHandlerMock implements LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {
        @Override
        public MutableHttpResponse<?> logout(HttpRequest<?> request) {
            return HttpResponse.ok();
        }
    }

    @Requires(property = "spec.name", value = REACTIVE_SPEC)
    @Singleton
    static class CustomAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            return Publishers.just(Authentication.build("sherlock"));
        }
    }
}
