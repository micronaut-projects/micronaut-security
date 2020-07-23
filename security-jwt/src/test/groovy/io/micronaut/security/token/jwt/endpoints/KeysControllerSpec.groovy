package io.micronaut.security.token.jwt.endpoints

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification
import spock.lang.Unroll

import javax.inject.Singleton

class KeysControllerSpec extends Specification {

    @Unroll
    def "#path responds a JSON Web Key Set payload"(String path) {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                 : 'keyscontrollerspec',
                'micronaut.security.endpoints.keys.path': path,

        ], Environment.TEST)
        RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

        when:
        HttpResponse<Map> response = client.toBlocking().exchange(HttpRequest.GET(path),  Map)

        then:
        response.status == HttpStatus.OK

        and:
        response.body().containsKey('keys')
        response.body()['keys'].size() == 1
        response.body()['keys'][0].containsKey('kty')
        response.body()['keys'][0].containsKey('alg')
        response.body()['keys'][0].containsKey('kid')
        response.body()['keys'][0].containsKey('use')
        response.body()['keys'][0].containsKey('e')
        response.body()['keys'][0].containsKey('n')

        cleanup:
        client.close()
        embeddedServer.close()

        where:
        path << ['/keys', '/jwks.json']
    }
    
    @Singleton
    @Requires(property = 'spec.name', value = 'keyscontrollerspec')
    static class RSAJwkProvider implements JwkProvider {
        private RSAKey jwk

        RSAJwkProvider() {

            String keyId = UUID.randomUUID().toString()
            try {
                this.jwk = new RSAKeyGenerator(2048)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                        .keyID(keyId) // give the key a unique ID
                        .generate()

            } catch (JOSEException e) {

            }
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            [jwk]
        }
    }
}
