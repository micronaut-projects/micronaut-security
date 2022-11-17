package io.micronaut.security.authentication

import io.micronaut.security.testutils.EmbeddedServerSpecification
class DefaultAuthorizationExceptionHandlerContextPathSpec extends EmbeddedServerSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
        ]
    }

    void "uses context path"() {
        expect:
        '/foo/' == applicationContext.getBean(DefaultAuthorizationExceptionHandler).getRedirectUri(null, new AuthorizationException(null))
    }
}
