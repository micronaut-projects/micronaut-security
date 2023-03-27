package io.micronaut.security.config

import io.micronaut.security.testutils.ApplicationContextSpecification

class InterceptUrlMapConverterContextPathSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.intercept-url-map': [[pattern: '/father', 'http-method': 'GET', 'access': ['isAuthenticated()']]],
        ]
    }

    void "intercept-url-patterns are not prepended with the context path by default"() {
        expect:
        applicationContext.getBean(SecurityConfiguration)
                .interceptUrlMap.stream()
                .map(InterceptUrlMapPattern::getPattern)
                .noneMatch(p -> p.startsWith("/foo"))
    }
}
