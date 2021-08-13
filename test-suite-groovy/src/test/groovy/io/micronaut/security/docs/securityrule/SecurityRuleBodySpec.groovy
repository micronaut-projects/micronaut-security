package io.micronaut.security.docs.securityrule

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification

class SecurityRuleBodySpec extends EmbeddedServerSpecification {

    @Override
    String getOpenIdClientName() {
        null
    }

    void "You can create a AOP to read HTTP Request body and create a similar annotation as @Secured"() {
        given:
        String expected = 'John real name is Aegon'

        when:
        String secret = client.retrieve(HttpRequest.POST('/got/secret', [name: 'George R.R. Martin']), String)

        then:
        noExceptionThrown()
        expected == secret

        when:
        client.retrieve(HttpRequest.POST('/got/secret', [name: 'Sergio']))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }
}
