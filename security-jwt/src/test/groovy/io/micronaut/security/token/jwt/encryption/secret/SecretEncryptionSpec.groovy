package io.micronaut.security.token.jwt.encryption.secret

import io.micronaut.context.ApplicationContext
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import spock.lang.Specification

class SecretEncryptionSpec extends Specification {

    //tag::yamlconfig[]
    private final static String yamlConfig = """
micronaut:
  security:
    token:
      jwt:
        encryptions:
          secret:
            generator:
              secret: pleaseChangeThisSecretForANewOne
              jwe-algorithm: dir
              encryption-method: A256GCM
"""
    //end::yamlconfig[]

    void "SecretEncryption constructor does not raise exception if jwe algorithm and encryption method set are valid"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'micronaut.security.token.jwt.encryptions.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.token.jwt.encryptions.secret.generator.jwe-algorithm': 'dir',
                'micronaut.security.token.jwt.encryptions.secret.generator.encryption-method': 'A256GCM',
        ])

        when:
        ctx.getBean(SecretEncryptionFactory)

        then:
        noExceptionThrown()

        when:
        ctx.getBean(SecretEncryptionConfiguration)

        then:
        noExceptionThrown()

        when:
        EncryptionConfiguration encryptionConfiguration = ctx.getBean(EncryptionConfiguration)

        then:
        noExceptionThrown()

        encryptionConfiguration instanceof SecretEncryption

        cleanup:
        ctx.close()
    }
}
