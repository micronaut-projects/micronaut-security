package io.micronaut.security.token.basicauth

import io.micronaut.context.ApplicationContext
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import spock.lang.Specification

class BasicAuthTokenValidatorSpec extends Specification {

    def "BasicAuthTokenValidator is loaded because by default security is turn on"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run()

        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator not loaded if micronaut.security.enabled=false"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.enabled': false])

        expect:
        !applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator is loaded if micronaut.security.enabled=true"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.enabled': true])

        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }

    def "BasicAuthTokenValidator is loaded if micronaut.security.basic-auth.enabled=false"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.basic-auth.enabled': false
        ])

        expect:
        !applicationContext.containsBean(BasicAuthAuthenticationFetcher)

        cleanup:
        applicationContext.close()
    }
}
