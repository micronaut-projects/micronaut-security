package io.micronaut.security.propagation

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter

class TokenPropagationHttpClientFilterDisabledExplicitlySpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.writer.header.enabled': true,
                'micronaut.security.token.propagation.enabled'  : false,
        ]
    }

    void "TokenPropagationHttpClientFilter is disabled when propagation enabled set to false explicitly"() {
        when:
        applicationContext.getBean(TokenPropagationHttpClientFilter)

        then:
        thrown(NoSuchBeanException)
    }
}
