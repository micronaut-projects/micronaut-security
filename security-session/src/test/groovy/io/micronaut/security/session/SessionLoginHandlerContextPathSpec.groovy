package io.micronaut.security.session

import io.micronaut.core.util.StringUtils
import io.micronaut.security.testutils.EmbeddedServerSpecification

class SessionLoginHandlerContextPathSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.authentication': 'session'
        ]
    }

    void "uses context path"() {
        expect:
        '/foo/' == applicationContext.getBean(SessionLoginHandler).loginFailure
        '/foo/' == applicationContext.getBean(SessionLoginHandler).loginSuccess
    }
}
