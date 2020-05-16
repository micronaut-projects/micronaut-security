package io.micronaut.security.token.jwt.bearer

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.testutils.EmbeddedServerSpecification
import spock.lang.Unroll

class BearerEnabledSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.bearer.enabled': false,
        ]
    }

    @Unroll("if micronaut.security.enabled=true and m.s.token.jwt.enabled=true and m.s.token.jwt.bearer.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.token.jwt.bearer.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        embeddedServer.applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                AccessRefreshTokenLoginHandler,
                BearerTokenConfigurationProperties,
                BearerTokenReader,
        ]

        description = clazz.name
    }

}
