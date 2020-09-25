package io.micronaut.security.authentication

import spock.lang.Specification
import spock.lang.Unroll

class BasicAuthUtilsSpec extends Specification {

    void "BasicAuthAuthenticationFetcher::parseCredentials parse creds from Basic Auth Http header value"() {
        when:
        Optional<UsernamePasswordCredentials> creds = BasicAuthUtils.parseCredentials('Basic dXNlcjpwYXNzd29yZA==')

        then:
        creds.isPresent()
        creds.get().identity == 'user'
        creds.get().secret == 'password'
    }

    @Unroll("BasicAuthUtils::parseCredentials returns an empty optional if HTTP Authorization header value ( #value ) does not start with `Basic `")
    void "For HTTP Header Authroziation value which do not start with Basic BasicAuthAuthenticationFetcher::parseCredentials returns an empty optional"(String value) {
        when:
        Optional<UsernamePasswordCredentials> creds = BasicAuthUtils.parseCredentials(value)

        then:
        noExceptionThrown()
        !creds.isPresent()

        where:
        value << ['', '123', 'Basic', 'Basic ', 'Foooo dXNlcjpwYXNzd29yZA==']
    }
}
