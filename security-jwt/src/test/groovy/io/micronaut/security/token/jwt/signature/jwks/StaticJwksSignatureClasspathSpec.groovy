package io.micronaut.security.token.jwt.signature.jwks

import io.micronaut.security.testutils.ApplicationContextSpecification

class StaticJwksSignatureClasspathSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.token.jwt.signatures.jwks-static.foo.path': 'classpath:jwks/certs.json'
        ] as Map<String, Object>
    }

    void "load JSON jwks from resources"(){
        when:
        applicationContext.getBean(StaticJwksSignature)

        then:
        noExceptionThrown()
    }
}
