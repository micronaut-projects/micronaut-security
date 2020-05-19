package io.micronaut.security.token.jwt.endpoints

import io.micronaut.http.HttpRequest
import io.micronaut.testutils.EmbeddedServerSpecification

class KeysControllersWithNoJWKSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        ['micronaut.security.endpoints.keys.enabled': true]
    }

    void "keys JSON Object MUST have a keys member"() {
        when:
        String keysJson = client.retrieve(HttpRequest.GET("/keys"), String)

        then:
        keysJson == '{"keys":[]}'
    }
}
