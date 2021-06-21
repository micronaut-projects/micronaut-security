package io.micronaut.security.authentication

import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class BasicAuthAuthenticationFetcherSpec extends ApplicationContextSpecification {

    void "by default BasicAuthAuthenticationFetcher exists"() {
        expect:
        applicationContext.containsBean(BasicAuthAuthenticationFetcher)
    }

    void "BasicAuthAuthenticationFetcher::parseCredentials parse creds from Basic Auth Http header value"() {
        given:
        BasicAuthAuthenticationFetcher fetcher = applicationContext.getBean(BasicAuthAuthenticationFetcher)

        when:
        Optional<UsernamePasswordCredentials> creds = fetcher.parseCredentials('Basic dXNlcjpwYXNzd29yZA==')

        then:
        creds.isPresent()
        creds.get().identity == 'user'
        creds.get().secret == 'password'
    }

    @Unroll("BasicAuthAuthenticationFetcher::parseCredentials returns an empty optional if HTTP Authorization header value ( #value ) does not start with `Basic `")
    void "For HTTP Header Authroziation value which do not start with Basic BasicAuthAuthenticationFetcher::parseCredentials returns an empty optiona"(String value) {
        given:
        BasicAuthAuthenticationFetcher fetcher = applicationContext.getBean(BasicAuthAuthenticationFetcher)

        when:
        Optional<UsernamePasswordCredentials> creds = fetcher.parseCredentials(value)

        then:
        noExceptionThrown()
        !creds.isPresent()

        where:
        value << ['', '123', 'Basic', 'Basic ', 'Foooo dXNlcjpwYXNzd29yZA==']
    }
}
