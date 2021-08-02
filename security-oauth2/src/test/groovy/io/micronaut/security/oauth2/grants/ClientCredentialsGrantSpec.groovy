package io.micronaut.security.oauth2.grants

import com.fasterxml.jackson.databind.ObjectMapper
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Shared
import javax.validation.Validator

class ClientCredentialsGrantSpec extends ApplicationContextSpecification {

    @Shared
    Validator validator = applicationContext.getBean(Validator)

    @Shared
    ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper)

    void "ClientCredentialsGrant is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection( ClientCredentialsGrant)

        then:
        noExceptionThrown()
    }

    void "valid ClientCredentialsGrant does not trigger any constraint exception"() {
        when:
        ClientCredentialsGrant el = validClientCredentials()

        then:
        validator.validate(el).isEmpty()
    }

    void "grantType is required"() {
        given:
        ClientCredentialsGrant el = validClientCredentials()

        when:
        el.grantType = null

        then:
        !validator.validate(el).isEmpty()
    }
    void "scope is optional"() {
        given:
        ClientCredentialsGrant el = validClientCredentials()

        when:
        el.scope = null

        then:
        validator.validate(el).isEmpty()
    }

    void "snake case is used for Json serialization"() {
        given:
        ClientCredentialsGrant el = new ClientCredentialsGrant()
        el.scope = 'https%3A%2F%2Fgraph.microsoft.com%2F.default'

        when:
        String json = objectMapper.writeValueAsString(el)

        then:
        json.contains('grant_type')
        json.contains('scope')
    }

    void "grant defaults to client_credentails"() {
        expect:
        'client_credentials' == new ClientCredentialsGrant().grantType
    }

    void "toMap returns snake case keys"() {
        when:
        ClientCredentialsGrant grant = new ClientCredentialsGrant()
        Map<String, String> response = grant.toMap()

        then:
        ['grant_type': 'client_credentials'] == response

        when:
        grant.scope = 'https%3A%2F%2Fgraph.microsoft.com%2F.default'
        response = grant.toMap()

        then:
        ['grant_type': 'client_credentials', 'scope': 'https%3A%2F%2Fgraph.microsoft.com%2F.default'] == response
    }

    static ClientCredentialsGrant validClientCredentials() {
        new ClientCredentialsGrant()
    }
}
