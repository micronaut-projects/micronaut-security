package io.micronaut.security.token.writer

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class HttpHeaderTokenPropagatorDisabledSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    @AutoCleanup ApplicationContext context = ApplicationContext.run([
            (SPEC_NAME_PROPERTY):getClass().simpleName
    ], Environment.TEST)

    void "HttpHeaderTokenPropagator is enabled by default"() {
        when:
        context.getBean(HttpHeaderTokenPropagator)

        then:
        noExceptionThrown()
    }
}
