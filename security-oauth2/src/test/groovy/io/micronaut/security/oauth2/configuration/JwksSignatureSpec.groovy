package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature
import spock.lang.Specification

class JwksSignatureSpec extends Specification {

    void "test a signature is created if configuration is provided"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'spec.name': getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.token.jwt.enabled': true,
                'micronaut.security.oauth2.clients.foo.openid.jwks-uri': 'YYYY',
                'micronaut.security.oauth2.clients.bar.client-id': 'x',
        ], Environment.TEST)

        when:
        def signature = context.getBeansOfType(JwksSignature)

        then:
        signature.size() == 1
    }
}
