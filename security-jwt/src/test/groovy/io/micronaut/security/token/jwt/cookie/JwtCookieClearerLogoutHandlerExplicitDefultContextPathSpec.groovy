package io.micronaut.security.token.jwt.cookie


import io.micronaut.security.testutils.EmbeddedServerSpecification

class JwtCookieClearerLogoutHandlerExplicitDefultContextPathSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': '/',
                'micronaut.security.authentication': 'cookie'
        ]
    }

    void "uses explicit default context path"() {
        expect:
        '/' == applicationContext.getBean(JwtCookieClearerLogoutHandler).logout
    }
}
