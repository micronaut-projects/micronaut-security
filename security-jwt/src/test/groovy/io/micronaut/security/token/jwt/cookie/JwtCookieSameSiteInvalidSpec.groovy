package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification
import spock.lang.Unroll

class JwtCookieSameSiteInvalidSpec extends Specification {

    @Unroll
    void "application fails to start with a ConfigurationException if #property has an invalid value"(String property) {
        when:
        ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwtCookieSameSiteInvalidSpec',
                'micronaut.security.authentication': 'cookie',
                (property): 'nonesense',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]).close()

        then:
        Exception e = thrown()
        ConfigurationException cause = rootCause(e) as ConfigurationException
        cause.message.contains(property)
        cause.message.contains('nonesense')

        where:
        property << [
                'micronaut.security.token.cookie.cookie-same-site',
                'micronaut.security.token.refresh.cookie.cookie-same-site',
        ]
    }

    private static Throwable rootCause(Throwable t) {
        while (!(t instanceof ConfigurationException) && t.cause != null) {
            t = t.cause
        }
        t
    }
}
