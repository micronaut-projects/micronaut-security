package io.micronaut.docs.websockets

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.reader.TokenReader
import io.micronaut.websocket.WebSocketBroadcaster
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
import spock.lang.Issue
import spock.util.concurrent.PollingConditions
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.function.Predicate

class HomePageSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'HomePageSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.intercept-url-map'                           : [
                        [
                                pattern        : '/assets/*',
                                ('http-method'): 'GET',
                                'access'       : ['isAnonymous()']
                        ]
                ],
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.router.static-resources.default.enabled'              : true,
                'micronaut.router.static-resources.default.mapping'              : '/assets/**',
                'micronaut.router.static-resources.default.paths'                : ['classpath:websockets'],
        ]
    }

    private Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        LocalDateTime time = LocalDateTime.now()
        time = time.plusDays(1)
        ZoneId zoneId = ZoneId.systemDefault()
        long expiration = time.atZone(zoneId).toEpochSecond()
        Map<String, Object> claims = [sub: 'john']
        claims.exp = expiration

        tokenGenerator.generateToken(claims)
    }

    @Issue("https://github.com/micronaut-projects/micronaut-core/issues/5618")
    def "check websocket connects"() {
        expect:
        embeddedServer.applicationContext.containsBean(CustomAuthenticationProvider)
        embeddedServer.applicationContext.containsBean(ParamTokenReader)
        embeddedServer.applicationContext.registerSingleton(new WebsocketsHtmlProvider(baseUrl))

        when:
        TokenGenerator tokenGenerator = embeddedServer.applicationContext.getBean(JwtTokenGenerator)

        then:
        noExceptionThrown()

        when:
        Optional<String> accessToken = generateJwt(tokenGenerator)

        then:
        accessToken.isPresent()

        when:
        WebSocketsHomePage homePage = browser.to(WebSocketsHomePage, accessToken.get())

        then:
        browser.at(WebSocketsHomePage)

        and:
        new PollingConditions(timeout: 3).eventually {
            println homePage.status()
            homePage.receivedMessages() == ['joined!']
            !homePage.sentMessages()
        }

        when:
        homePage.send('Hello')

        then:
        new PollingConditions().eventually {
            homePage.receivedMessages() == ['joined!', 'Hello']
            homePage.sentMessages() == ['Hello']
        }

        when:
        homePage.close()

        then:
        homePage.status().contains('Disconnected')
    }

    @Requires(property = 'spec.name', value = 'HomePageSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('john')])
        }
    }

    @Requires(property = 'spec.name', value = 'HomePageSpec')
    @Singleton
    static class ParamTokenReader implements TokenReader {
        @Override
        Optional<String> findToken(HttpRequest<?> request) {
            Optional.ofNullable(request.getParameters().get("token"))
        }
    }

    @Requires(property = 'spec.name', value = 'HomePageSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class HomeController {
        @Inject
        WebsocketsHtmlProvider websocketsHtmlProvider

        @Produces(MediaType.TEXT_HTML)
        @Get
        String index(@Nullable String jwt) {
            websocketsHtmlProvider.html(jwt)
        }
    }

    @Requires(property = 'spec.name', value = 'HomePageSpec')
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

    @Requires(property = 'spec.name', value = 'HomePageSpec')
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
