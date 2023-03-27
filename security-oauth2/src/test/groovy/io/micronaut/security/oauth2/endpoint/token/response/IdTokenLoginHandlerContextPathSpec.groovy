package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.security.testutils.EmbeddedServerSpecification

class IdTokenLoginHandlerContextPathSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.authentication': 'idtoken'
        ]
    }

    void "uses context path"() {
        expect:
        '/foo/' == applicationContext.getBean(IdTokenLoginHandler).loginFailure
        '/foo/' == applicationContext.getBean(IdTokenLoginHandler).loginSuccess
        '/foo/' == applicationContext.getBean(IdTokenLoginHandler).refresh
    }
}
