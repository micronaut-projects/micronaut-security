package io.micronaut.security.token.jwt.cookie


import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.token.cookie.TokenCookieClearerLogoutHandler

class JwtCookieClearerLogoutHandlerContextPathSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.authentication': 'cookie'
        ]
    }

    void "uses context path"() {
        expect:
        '/foo/' == applicationContext.getBean(TokenCookieClearerLogoutHandler).logout
    }
}
