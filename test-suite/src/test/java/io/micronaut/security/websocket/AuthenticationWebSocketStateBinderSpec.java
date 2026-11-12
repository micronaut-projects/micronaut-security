package io.micronaut.security.websocket;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.websocket.WebSocketBroadcaster;
import io.micronaut.websocket.WebSocketClient;
import io.micronaut.websocket.WebSocketSession;
import io.micronaut.websocket.annotation.ClientWebSocket;
import io.micronaut.websocket.annotation.OnMessage;
import io.micronaut.websocket.annotation.OnOpen;
import io.micronaut.websocket.annotation.ServerWebSocket;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest
@Property(name = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
class AuthenticationWebSocketStateBinderSpec {
    @Test
    void authenticationCanBeInjectedIntoWebsocketOnOpen(TokenGenerator tokenGenerator,
                                                        WebSocketClient wsClient,
                                                        EmbeddedServer server) {
        //when:
        Optional<String> accessToken = generateJwt(tokenGenerator);

        //then:
        assertTrue(accessToken.isPresent());

        //when:
        String token = accessToken.get();
        MutableHttpRequest<?> request = HttpRequest.GET("http://localhost:" + server.getPort() + "/auth-echo").bearerAuth(token);
        AuthenticationEchoClientWebSocket client = Flux.from(wsClient.connect(AuthenticationEchoClientWebSocket.class, request)).blockFirst();

        //then:
        await().atMost(5, SECONDS).until(() -> client.receivedMessages().equals(List.of("joined! john")));

        //cleanup:
        client.close();
    }

    private static Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        Integer expiration = Math.toIntExact(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toEpochSecond());
        return tokenGenerator.generateToken(Authentication.build("john"), expiration);
    }

    @Requires(property = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @ServerWebSocket("/auth-echo")
    static class AuthenticationEchoServerWebSocket {

        private final WebSocketBroadcaster broadcaster;

        AuthenticationEchoServerWebSocket(WebSocketBroadcaster broadcaster) {
            this.broadcaster = broadcaster;
        }

//tag::onOpen[]
        @OnOpen
        void onOpen(WebSocketSession session, Authentication authentication) {
            broadcaster.broadcastSync("joined! " + authentication.getName(), isValid(session));
        }
//end::onOpen[]

        @OnMessage
        void onMessage(String message, WebSocketSession session, Authentication authentication) {
            broadcaster.broadcastSync("I received a message from " + authentication.getName(), isValid(session));
        }

        private static Predicate<WebSocketSession> isValid(WebSocketSession session) {
            return s -> s.equals(session);
        }
    }

    @Requires(property = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
    @ClientWebSocket("/auth-echo")
    static abstract class AuthenticationEchoClientWebSocket implements AutoCloseable {

        private WebSocketSession session;
        private final List<String> replies = new CopyOnWriteArrayList<>();

        @OnOpen
        void onOpen(WebSocketSession session) {
            this.session = session;
        }

        @OnMessage
        void onMessage(String message) {
            replies.add(message);
        }

        abstract void send(String message);

        List<String> receivedMessages() {
            return replies;
        }

        @Override
        public void close() {
            session.close();
        }
    }
}
