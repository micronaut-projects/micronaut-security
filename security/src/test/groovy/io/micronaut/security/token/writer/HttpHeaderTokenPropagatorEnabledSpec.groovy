package io.micronaut.security.token.writer

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class HttpHeaderTokenPropagatorEnabledSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    @AutoCleanup ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.propagation.header.enabled': true,
            (SPEC_NAME_PROPERTY):getClass().simpleName
    ], Environment.TEST)

    void "JwtHttpClientFilter is enabled if you set micronaut.security.token.jwt.propagation.enabled"() {
        when:
        context.getBean(HttpHeaderTokenPropagator)

        then:
        noExceptionThrown()
    }
}
