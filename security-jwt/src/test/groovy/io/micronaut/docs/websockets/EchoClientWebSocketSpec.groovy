package io.micronaut.docs.websockets

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.websocket.WebSocketBroadcaster
import io.micronaut.websocket.WebSocketClient
import io.micronaut.websocket.WebSocketSession
import io.micronaut.websocket.annotation.ClientWebSocket
import io.micronaut.websocket.annotation.OnClose
import io.micronaut.websocket.annotation.OnMessage
import io.micronaut.websocket.annotation.OnOpen
import io.micronaut.websocket.annotation.ServerWebSocket
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import reactor.core.publisher.Flux
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.time.LocalDateTime
import java.time.ZoneId
import java.util.function.Predicate

class EchoClientWebSocketSpec extends Specification {

    @Shared
    Map<String, Object> conf = [
            'spec.name'                                                      : 'EchoClientWebSocketSpec',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, conf)

    @Shared
    @AutoCleanup
    WebSocketClient wsClient = embeddedServer.applicationContext.createBean(WebSocketClient, embeddedServer.URL)

    private Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        LocalDateTime time = LocalDateTime.now()
        time = time.plusDays(1)
        ZoneId zoneId = ZoneId.systemDefault()
        long expiration = time.atZone(zoneId).toEpochSecond()
        Map<String, Object> claims = [sub: 'john']
        claims.exp = expiration

        tokenGenerator.generateToken(claims)
    }

    def "check websocket connects"() {

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
        HttpRequest request = HttpRequest.GET("/echo").bearerAuth(token)

        EchoClientWebSocket echoClientWebSocket = Flux.from(wsClient.connect(EchoClientWebSocket, request)).blockFirst()

        then:
        new PollingConditions().eventually {
            echoClientWebSocket.receivedMessages() == ['joined!']
        }

        when:
        echoClientWebSocket.send('Hello')

        then:
        new PollingConditions().eventually {
            echoClientWebSocket.receivedMessages() == ['joined!', 'Hello']
        }

        cleanup:
        echoClientWebSocket.close()
    }

    @Requires(property = 'spec.name', value = 'EchoClientWebSocketSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('john')])
        }
    }

    @Requires(property = 'spec.name', value = 'EchoClientWebSocketSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @ServerWebSocket("/echo")
    static class EchoServerWebSocket {
        public static final String JOINED = "joined!"
        public static final String DISCONNECTED = "Disconnected!"

        @Inject
        WebSocketBroadcaster broadcaster

        @OnOpen
        void onOpen(WebSocketSession session) {
            broadcaster.broadcastSync(JOINED, isValid(session))
        }

        @OnMessage
        void onMessage(String message, WebSocketSession session) {
            broadcaster.broadcastSync(message, isValid(session))
        }

        @OnClose
        void onClose(WebSocketSession session) {
            broadcaster.broadcastSync(DISCONNECTED, isValid(session))
        }

        private static Predicate<WebSocketSession> isValid(WebSocketSession session) {
             return { s -> (s == session) }
        }
    }

    @Requires(property = 'spec.name', value = 'EchoClientWebSocketSpec')
    @ClientWebSocket("/echo")
    static abstract class EchoClientWebSocket implements AutoCloseable {

        static final String RECEIVED = 'RECEIVED:'

        private static final Logger LOG = LoggerFactory.getLogger(EchoClientWebSocket.class)

        private WebSocketSession session
        private List<String> replies = new ArrayList<>()

        @OnOpen
        void onOpen(WebSocketSession session) {
            this.session = session
        }
        List<Map> getReplies() {
            return replies
        }

        @OnMessage
        void onMessage(String message) {
            replies.add(RECEIVED + message)
        }

        abstract void send(String message)

        List<String> receivedMessages() {
            filterMessagesByType(RECEIVED)
        }

        List<String> filterMessagesByType(String type) {
            replies.findAll { String str ->
                str.contains(type)
            }.collect { String str ->
                str.replaceAll(type, '')
            }
        }
    }
}