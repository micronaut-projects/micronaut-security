package io.micronaut.docs.websockets

import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.testutils.GebEmbeddedServerSpecification
import spock.util.concurrent.PollingConditions

import java.time.LocalDateTime
import java.time.ZoneId

class HomePageSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'websockets'
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

    Optional<String> generateJwt(TokenGenerator tokenGenerator) {
        LocalDateTime time = LocalDateTime.now()
        time = time.plusDays(1)
        ZoneId zoneId = ZoneId.systemDefault()
        long expiration = time.atZone(zoneId).toEpochSecond()
        Map<String, Object> claims = [sub: 'john']
        claims.exp = expiration

        tokenGenerator.generateToken(claims)
    }

    def "check websocket connects"() {
        given:
        browser.baseUrl = embeddedServer.URL.toString()

        expect:
        embeddedServer.applicationContext.containsBean(MockAuthenticationProvider)
        embeddedServer.applicationContext.containsBean(ParamTokenReader)

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
}
