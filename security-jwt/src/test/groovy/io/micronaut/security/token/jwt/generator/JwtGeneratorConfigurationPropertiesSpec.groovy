package io.micronaut.security.token.jwt.generator

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class JwtGeneratorConfigurationPropertiesSpec extends Specification {
    @Deprecated
    void "micronaut.security.token.jwt.generator.access-token-expiration populates AccessTokenConfiguration#getExpiration"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.token.jwt.generator.access-token-expiration': 1])
        expect:
        applicationContext.getProperty(JwtGeneratorConfigurationProperties.PREFIX + ".access-token-expiration", Integer).isPresent()
        applicationContext.getProperty(JwtGeneratorConfigurationProperties.PREFIX + ".access-token-expiration", Integer).get() == 1
        applicationContext.getBean(JwtGeneratorConfigurationProperties).accessTokenExpiration == 1
        applicationContext.getBean(AccessTokenConfiguration).expiration == 1

        cleanup:
        applicationContext.close()
    }

    @Deprecated
    void "micronaut.security.token.jwt.generator.access-token.expiration takes precedence over micronaut.security.token.jwt.generator.access-token-expiration"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.token.jwt.generator.access-token-expiration': 1,
                'micronaut.security.token.jwt.generator.access-token.expiration': 5
        ])
        expect:
        applicationContext.getProperty(JwtGeneratorConfigurationProperties.PREFIX + ".access-token-expiration", Integer).isPresent()
        applicationContext.getProperty(JwtGeneratorConfigurationProperties.PREFIX + ".access-token-expiration", Integer).get() == 1
        applicationContext.getBean(AccessTokenConfiguration).expiration == 5
        applicationContext.getBean(JwtGeneratorConfigurationProperties).accessTokenExpiration == 5

        cleanup:
        applicationContext.close()
    }

}
