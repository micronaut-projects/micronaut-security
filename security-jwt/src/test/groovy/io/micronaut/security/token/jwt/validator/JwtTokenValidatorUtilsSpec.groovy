package io.micronaut.security.token.jwt.validator

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import spock.lang.Specification

import java.security.SecureRandom

class JwtTokenValidatorUtilsSpec extends Specification {

    void "compatible signature configuration are used first"() {
        when:
        SignedJWT jwt = buildSignedJWT()
        def incompatibleSignatureConfiguration = Mock(SignatureConfiguration) {
            1 * supports(_) >> false
            0 * verify(_)
        }
        def compatibleSignatureConfiguration = Mock(SignatureConfiguration) {
            1 * supports(_) >> true
            1 * verify(_) >> Optional.of(jwt)
        }

        Optional<JWT> result = JwtTokenValidatorUtils.validateSignedJWTSignature(jwt, [incompatibleSignatureConfiguration,
                                                                                 compatibleSignatureConfiguration])

        then:
        result.isPresent()
    }

    void "if no compatible signature configuration, every configuration is attempted"() {
        when:
        SignedJWT jwt = buildSignedJWT()
        def incompatibleSignatureConfiguration = Mock(SignatureConfiguration) {
            1 * supports(_) >> false
            1 * verify(_) >> Optional.empty()
        }
        def compatibleSignatureConfiguration = Mock(SignatureConfiguration) {
            1 * supports(_) >> false
            1 * verify(_) >> Optional.of(jwt)
        }
        Optional<JWT> result = JwtTokenValidatorUtils.validateSignedJWTSignature(jwt, [incompatibleSignatureConfiguration,
                                                                                       compatibleSignatureConfiguration])
        then:
        result.isPresent()
    }

    private SignedJWT buildSignedJWT() {
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"))
        byte[] sharedKey = new byte[32]
        new SecureRandom().nextBytes(sharedKey)
        jwsObject.sign(new MACSigner(sharedKey))
        JWT jwt = JWTParser.parse(jwsObject.serialize())
        assert jwt instanceof SignedJWT
        (SignedJWT) jwt
    }
}
