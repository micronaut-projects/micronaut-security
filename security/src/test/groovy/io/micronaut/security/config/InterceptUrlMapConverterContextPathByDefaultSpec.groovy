package io.micronaut.security.config

import io.micronaut.core.util.StringUtils
import io.micronaut.security.testutils.ApplicationContextSpecification

class InterceptUrlMapConverterContextPathByDefaultSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.server.context-path': 'foo',
                'micronaut.security.intercept-url-map-prepend-pattern-with-context-path': StringUtils.TRUE,
                'micronaut.security.intercept-url-map': [[pattern: '/father', 'http-method': 'GET', 'access': ['isAuthenticated()']]],
        ]
    }

    void "intercept-url-patterns are prepended with the context path"() {
        expect:
        applicationContext.getBean(SecurityConfiguration)
                .interceptUrlMap.stream()
                .map(InterceptUrlMapPattern::getPattern)
                .allMatch(p -> p.startsWith("/foo"))
    }
}
