package io.micronaut.security.websockets

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import io.micronaut.websocket.WebSocketBroadcaster
import io.micronaut.websocket.WebSocketClient
import io.micronaut.websocket.WebSocketSession
import io.micronaut.websocket.annotation.ClientWebSocket
import io.micronaut.websocket.annotation.OnMessage
import io.micronaut.websocket.annotation.OnOpen
import io.micronaut.websocket.annotation.ServerWebSocket
import jakarta.inject.Inject
import reactor.core.publisher.Flux
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.time.LocalDateTime
import java.time.ZoneId
import java.util.concurrent.CopyOnWriteArrayList
import java.util.function.Predicate

@MicronautTest
@Property(name = 'spec.name', value = 'AuthenticationWebSocketStateBinderSpec')
@Property(name = 'micronaut.security.token.jwt.signatures.secret.generator.secret', value = 'pleaseChangeThisSecretForANewOne')
class AuthenticationWebSocketStateBinderSpec extends Specification {
    @Inject
    BeanContext beanContext

    @Inject
    TokenGenerator tokenGenerator

    @Inject
    WebSocketClient wsClient

    @Inject
    EmbeddedServer server

    def "authentication can be injected into websocket on open"() {
        when:
        Optional<String> accessToken = generateJwt(tokenGenerator)

        then:
        accessToken.isPresent()

        when:
        String token = accessToken.get()
        HttpRequest request = HttpRequest.GET("http://localhost:${server.port}/auth-echo").bearerAuth(token)
        AuthenticationEchoClientWebSocket client = Flux.from(wsClient.connect(AuthenticationEchoClientWebSocket, request)).blockFirst()

        then:
        new PollingConditions().eventually {
            client.receivedMessages() == ['joined! john']
        }

        when:
        client.send("hello")

        then:
        new PollingConditions().eventually {
            client.receivedMessages() == ['joined! john', 'I received a message from john']
        }

        cleanup:
        client.close()
    }

    private static Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        Integer expiration = LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toEpochSecond()
        return tokenGenerator.generateToken(Authentication.build("john"), expiration)
    }

    @Requires(property = 'spec.name', value = 'AuthenticationWebSocketStateBinderSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @ServerWebSocket("/auth-echo")
    static class AuthenticationEchoServerWebSocket {

        private final WebSocketBroadcaster broadcaster

        AuthenticationEchoServerWebSocket(WebSocketBroadcaster broadcaster) {
            this.broadcaster = broadcaster
        }

//tag::onOpen[]
        @OnOpen
        void onOpen(WebSocketSession session, Authentication authentication) {
            broadcaster.broadcastSync("joined! ${authentication.name}", isValid(session))
        }
//end::onOpen[]

        @OnMessage
        void onMessage(String message, WebSocketSession session, Authentication authentication) {
            broadcaster.broadcastSync("I received a message from " + authentication.name, isValid(session))
        }

        private static Predicate<WebSocketSession> isValid(WebSocketSession session) {
            return { s -> (s == session) } as Predicate<WebSocketSession>
        }
    }

    @Requires(property = 'spec.name', value = 'AuthenticationWebSocketStateBinderSpec')
    @ClientWebSocket("/auth-echo")
    static abstract class AuthenticationEchoClientWebSocket implements AutoCloseable {

        private WebSocketSession session
        private final List<String> replies = new CopyOnWriteArrayList<>()

        @OnOpen
        void onOpen(WebSocketSession session) {
            this.session = session
        }

        @OnMessage
        void onMessage(String message) {
            replies.add(message)
        }

        abstract void send(String message)

        List<String> receivedMessages() {
            replies
        }

        @Override
        void close() {
            session.close()
        }
    }
}
