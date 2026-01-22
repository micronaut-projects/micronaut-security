package io.micronaut.security.websocket.bind

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.websocket.WebSocketBroadcaster
import io.micronaut.websocket.WebSocketClient
import io.micronaut.websocket.WebSocketSession
import io.micronaut.websocket.annotation.ClientWebSocket
import io.micronaut.websocket.annotation.OnMessage
import io.micronaut.websocket.annotation.OnOpen
import io.micronaut.websocket.annotation.ServerWebSocket
import reactor.core.publisher.Flux
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.time.LocalDateTime
import java.time.ZoneId
import java.util.concurrent.CopyOnWriteArrayList
import java.util.function.Predicate

class AuthenticationWebSocketStateBinderSpec extends Specification {

    @Shared
    Map<String, Object> conf = [
            'spec.name'                                                      : 'AuthenticationWebSocketStateBinderSpec',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, conf)

    @Shared
    @AutoCleanup
    WebSocketClient wsClient = embeddedServer.applicationContext.createBean(WebSocketClient, embeddedServer.URL)

    private Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        long expiration = LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toEpochSecond()
        Map<String, Object> claims = [sub: 'john']
        claims.exp = expiration

        tokenGenerator.generateToken(claims)
    }

    def "authentication can be injected into websocket on open"() {
        expect:
        wsClient != null

        when:
        TokenGenerator tokenGenerator = embeddedServer.applicationContext.getBean(JwtTokenGenerator)

        then:
        noExceptionThrown()

        when:
        Optional<String> accessToken = generateJwt(tokenGenerator)

        then:
        accessToken.isPresent()

        when:
        String token = accessToken.get()
        HttpRequest request = HttpRequest.GET("/auth-echo").bearerAuth(token)
        AuthenticationEchoClientWebSocket client = Flux.from(wsClient.connect(AuthenticationEchoClientWebSocket, request)).blockFirst()

        then:
        new PollingConditions().eventually {
            client.receivedMessages() == ['joined! john']
        }

        cleanup:
        client?.close()
    }

    @Requires(property = 'spec.name', value = 'AuthenticationWebSocketStateBinderSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @ServerWebSocket("/auth-echo")
    static class AuthenticationEchoServerWebSocket {

        private final WebSocketBroadcaster broadcaster

        AuthenticationEchoServerWebSocket(WebSocketBroadcaster broadcaster) {
            this.broadcaster = broadcaster
        }

        @OnOpen
        void onOpen(WebSocketSession session, Authentication authentication) {
            broadcaster.broadcastSync("joined! ${authentication.name}", isValid(session))
        }

        @OnMessage
        void onMessage(String message, WebSocketSession session) {
            broadcaster.broadcastSync(message, isValid(session))
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
            session?.close()
        }
    }
}
