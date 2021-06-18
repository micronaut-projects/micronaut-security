package io.micronaut.security.token.jwt.endpoints

import com.nimbusds.jose.jwk.JWK
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

class KeysControllersWithNoJWKSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'KeysControllersWithNoJWKSpec'
    }

    void "keys JSON Object MUST have a keys member"() {
        when:
        String keysJson = client.retrieve(HttpRequest.GET("/keys"), String)

        then:
        keysJson == '{"keys":[]}'
    }

    @Requires(property = "spec.name", value = 'KeysControllersWithNoJWKSpec')
    @Singleton
    static class CustomJwkProvider implements JwkProvider {

        @Override
        List<JWK> retrieveJsonWebKeys() {
            []
        }
    }
}
