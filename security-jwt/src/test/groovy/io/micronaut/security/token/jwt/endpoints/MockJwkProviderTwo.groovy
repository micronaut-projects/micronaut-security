package io.micronaut.security.token.jwt.endpoints

import com.nimbusds.jose.jwk.JWK
import io.micronaut.context.annotation.Requires
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "keyscontrollerwithmultiplekeys")
@Singleton
class MockJwkProviderTwo implements JwkProvider {

    @Override
    List<JWK> retrieveJsonWebKeys() {
        [JWK.parse("{\"kty\": \"EC\", \"crv\": \"P-256\", \"kid\": \"2\", \"x\": \"finSmmPigw1OpDEGHovLUYbDyknYSvlv09Uw--vDGxo\", \"y\": \"EHT3BnKDe17MfLlkAuYFzUuui6vqXfcbWhanN-tonw4\" }")]
    }
}
