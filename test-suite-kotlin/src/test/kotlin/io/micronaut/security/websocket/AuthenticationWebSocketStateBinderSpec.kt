package io.micronaut.security.websocket

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import io.micronaut.websocket.WebSocketBroadcaster
import io.micronaut.websocket.WebSocketClient
import io.micronaut.websocket.WebSocketSession
import io.micronaut.websocket.annotation.ClientWebSocket
import io.micronaut.websocket.annotation.OnMessage
import io.micronaut.websocket.annotation.OnOpen
import io.micronaut.websocket.annotation.ServerWebSocket
import org.awaitility.Awaitility
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import reactor.core.publisher.Flux
import java.lang.AutoCloseable
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import java.util.concurrent.Callable
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.function.Predicate

@MicronautTest
@Property(name = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
@Property(
    name = "micronaut.security.token.jwt.signatures.secret.generator.secret",
    value = "pleaseChangeThisSecretForANewOne"
)
internal class AuthenticationWebSocketStateBinderSpec {
    @Test
    fun authenticationCanBeInjectedIntoWebsocketOnOpen(
        tokenGenerator: TokenGenerator,
        wsClient: WebSocketClient,
        server: EmbeddedServer
    ) {
        //when:
        val accessToken = generateJwt(tokenGenerator)

        //then:
        assertTrue(accessToken.isPresent)

        //when:
        val token = accessToken.get()
        val request: MutableHttpRequest<*> =
            HttpRequest.GET<Any>("http://localhost:" + server.getPort() + "/auth-echo").bearerAuth(token)
        val client = Flux.from(
            wsClient.connect(
                AuthenticationEchoClientWebSocket::class.java, request
            )
        ).blockFirst()!!

        //then:
        Awaitility.await().atMost(5, TimeUnit.SECONDS)
            .until(Callable { client.receivedMessages() == mutableListOf<String?>("joined! john") })

        //when:
        client.send("hello")

        //then:
        Awaitility.await().atMost(5, TimeUnit.SECONDS)
            .until(Callable { client.receivedMessages() == listOf("joined! john", "I received a message from john") })

        //cleanup:
        client.close()
    }

    @Requires(property = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @ServerWebSocket("/auth-echo")
    internal class AuthenticationEchoServerWebSocket(private val broadcaster: WebSocketBroadcaster) {
        //tag::onOpen[]
        @OnOpen
        fun onOpen(session: WebSocketSession, authentication: Authentication) {
            broadcaster.broadcastSync("joined! " + authentication.name, isValid(session))
        }
        //end::onOpen[]

        @OnMessage
        fun onMessage(message: String, session: WebSocketSession, authentication: Authentication) {
            broadcaster.broadcastSync("I received a message from " + authentication.name, isValid(session))
        }

        companion object {
            private fun isValid(session: WebSocketSession): Predicate<WebSocketSession> {
                return Predicate { s: WebSocketSession -> s == session }
            }
        }
    }

    @Requires(property = "spec.name", value = "AuthenticationWebSocketStateBinderSpec")
    @ClientWebSocket("/auth-echo")
    internal abstract class AuthenticationEchoClientWebSocket : AutoCloseable {
        private var session: WebSocketSession? = null
        private val replies: MutableList<String> = CopyOnWriteArrayList<String>()

        @OnOpen
        fun onOpen(session: WebSocketSession) {
            this.session = session
        }

        @OnMessage
        fun onMessage(message: String) {
            replies.add(message)
        }

        abstract fun send(message: String)

        fun receivedMessages(): MutableList<String> {
            return replies
        }

        override fun close() {
            session!!.close()
        }
    }

    companion object {
        private fun generateJwt(tokenGenerator: TokenGenerator): Optional<String> {
            val expiration =
                Math.toIntExact(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toEpochSecond())
            return tokenGenerator.generateToken(Authentication.build("john"), expiration)
        }
    }
}
