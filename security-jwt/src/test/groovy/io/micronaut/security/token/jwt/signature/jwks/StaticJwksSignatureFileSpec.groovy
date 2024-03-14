package io.micronaut.security.token.jwt.signature.jwks

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path;

class StaticJwksSignatureFileSpec extends Specification {

    void "load JSON jwks from disk"() {
        given:
        Path jwksFilePath = Files.createTempFile("micronaut-test-jwks-static", "json")
        try (OutputStream os = Files.newOutputStream(jwksFilePath)) {
                InputStream is = ClassLoader.getSystemResourceAsStream('jwks/certs.json')
                os.write(is.readAllBytes())
                os.close()
        }
        ApplicationContext applicationContext = ApplicationContext.run(
                ['micronaut.security.token.jwt.signatures.jwks-static.foo.path': 'file://' + jwksFilePath.toString()]
        )

        when:
        applicationContext.getBean(StaticJwksSignature)

        then:
        noExceptionThrown()
    }
}
