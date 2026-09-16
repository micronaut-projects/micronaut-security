import time
from abc import ABC, abstractmethod
from typing import Annotated

import java
from jakarta.inject import Inject
from java.lang import AutoCloseable
from java.util.concurrent import CopyOnWriteArrayList, TimeUnit
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest
from micronaut.runtime.server import EmbeddedServer
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule
from micronaut.security.token.generator import TokenGenerator
from micronaut.test.extensions.junit5.annotation import MicronautTest
from micronaut.websocket import WebSocketBroadcaster, WebSocketClient, WebSocketSession
from micronaut.websocket.annotation import ClientWebSocket, OnMessage, OnOpen, ServerWebSocket
from org.junit.jupiter.api import Test
from reactor.core.publisher import Flux

# TODO(python): java.type needed because the Python class is passed as the runtime type argument of
# WebSocketClient.connect(); the Python class object itself is not accepted as a Java Class
AuthenticationEchoClientWebSocketClass = java.type("micronaut.security.websocket.AuthenticationEchoClientWebSocket")


@MicronautTest
@Property(name="spec.name", value="AuthenticationWebSocketStateBinderSpec")
@Property(name="micronaut.security.token.jwt.signatures.secret.generator.secret", value="pleaseChangeThisSecretForANewOne")
class AuthenticationWebSocketStateBinderSpec:
    tokenGenerator: Annotated[TokenGenerator, Inject]
    wsClient: Annotated[WebSocketClient, Inject]
    server: Annotated[EmbeddedServer, Inject]

    @Test
    def test_authentication_can_be_injected_into_websocket_on_open(self):
        # when:
        accessToken = self.generate_jwt(self.tokenGenerator)

        # then:
        assert accessToken.isPresent()

        # when:
        token = accessToken.get()
        request = HttpRequest.GET("http://localhost:" + str(self.server.getPort()) + "/auth-echo").bearerAuth(token)
        client = Flux.from_(self.wsClient.connect(AuthenticationEchoClientWebSocketClass, request)).blockFirst()

        # then:
        for _ in range(50):
            if list(client.received_messages()) == ["joined! john"]:
                break
            TimeUnit.MILLISECONDS.sleep(100)
        assert list(client.received_messages()) == ["joined! john"]

        # cleanup:
        client.close()

    def generate_jwt(self, tokenGenerator: TokenGenerator):
        expiration = int(time.time()) + 24 * 60 * 60  # one day from now
        return tokenGenerator.generateToken(Authentication.build("john"), expiration)


@Requires(property="spec.name", value="AuthenticationWebSocketStateBinderSpec")
@Secured(SecurityRule.IS_AUTHENTICATED)
@ServerWebSocket("/auth-echo")
class AuthenticationEchoServerWebSocket:

    def __init__(self, broadcaster: WebSocketBroadcaster):
        self.broadcaster = broadcaster

    # tag::onOpen[]
    @OnOpen
    def onOpen(self, session: WebSocketSession, authentication: Authentication) -> None:
        self.broadcaster.broadcastSync("joined! " + authentication.getName(), self.is_valid(session))
    # end::onOpen[]

    @OnMessage
    def onMessage(self, message: str, session: WebSocketSession, authentication: Authentication) -> None:
        self.broadcaster.broadcastSync("I received a message from " + authentication.getName(), self.is_valid(session))

    def is_valid(self, session: WebSocketSession):
        return lambda s: s.equals(session)


@Requires(property="spec.name", value="AuthenticationWebSocketStateBinderSpec")
@ClientWebSocket("/auth-echo")
class AuthenticationEchoClientWebSocket(ABC, AutoCloseable):

    def __init__(self):
        self.session = None
        self.replies = CopyOnWriteArrayList()

    @OnOpen
    def onOpen(self, session: WebSocketSession) -> None:
        self.session = session

    @OnMessage
    def onMessage(self, message: str) -> None:
        self.replies.add(message)

    @abstractmethod
    def send(self, message: str) -> None:
        ...

    def received_messages(self) -> list[str]:
        return self.replies

    def close(self) -> None:
        self.session.close()
