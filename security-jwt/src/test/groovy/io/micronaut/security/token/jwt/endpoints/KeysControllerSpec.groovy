package io.micronaut.security.token.jwt.endpoints

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import jakarta.inject.Singleton
import spock.lang.Specification
import spock.lang.Unroll

class KeysControllerSpec extends Specification {

    @Unroll
    def "#path responds a JSON Web Key Set payload"(String path) {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                 : 'keyscontrollerspec',
                'micronaut.security.endpoints.keys.path': path,

        ])
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

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

    void "keys endpoint response carries Cache-Control public, max-age=3600 by default"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'keyscontrollerspec',
        ])
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        HttpResponse<Map> response = client.toBlocking().exchange(HttpRequest.GET('/keys'), Map)

        then:
        response.status == HttpStatus.OK
        response.header('Cache-Control') == 'public, max-age=3600'

        and:
        response.body()['keys'].size() == 1

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "micronaut.security.endpoints.keys.cache-max-age configures the Cache-Control max-age of the keys endpoint response"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'keyscontrollerspec',
                'micronaut.security.endpoints.keys.cache-max-age': '5m',
        ])
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        HttpResponse<Map> response = client.toBlocking().exchange(HttpRequest.GET('/keys'), Map)

        then:
        response.status == HttpStatus.OK
        response.header('Cache-Control') == 'public, max-age=300'

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "a cache-max-age of zero disables the Cache-Control header of the keys endpoint response"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'keyscontrollerspec',
                'micronaut.security.endpoints.keys.cache-max-age': '0s',
        ])
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        HttpResponse<Map> response = client.toBlocking().exchange(HttpRequest.GET('/keys'), Map)

        then:
        response.status == HttpStatus.OK
        response.header('Cache-Control') == null

        and:
        response.body()['keys'].size() == 1

        cleanup:
        client.close()
        embeddedServer.close()
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
