package io.micronaut.security.token.jwt.validator

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.security.authentication.Authentication
import io.micronaut.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class DefaultJwtAuthenticationFactorySpec extends ApplicationContextSpecification {

    @Subject
    @Shared
    DefaultJwtAuthenticationFactory factory = applicationContext.getBean(DefaultJwtAuthenticationFactory)

    void "authentication contains roles in JWT"() {
        given:
        JWT jwt = generateJWT()

        when:
        Optional<Authentication> authenticationOptional = factory.createAuthentication(jwt)

        then:
        authenticationOptional.isPresent()

        when:
        Authentication authentication = authenticationOptional.get()

        then:
        authentication.name == 'alice'
        authentication.getAttributes().containsKey('roles')
        authentication.getAttributes()['roles'] == ['ROLE_USER', 'ROLE_ADMIN']
    }

    private static JWT generateJWT() {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate()
        JWSSigner signer = new RSASSASigner(rsaJWK)
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .claim("roles", ['ROLE_USER', 'ROLE_ADMIN'])
                .build()
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                claimsSet)
        signedJWT.sign(signer)
        JWTParser.parse(signedJWT.serialize())
    }
}
