package io.micronaut.security.token.jwt.signature.ec

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import spock.lang.Specification

class ECSignatureConfigurationSpec extends Specification {

    String primaryKey = "{\"kty\":\"EC\",\"d\":\"_acu5mPBKeNNuxvlPx909IdpDFhhwBCfhRxRfbzwNhI\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"RtOqf4HOQO_IJYGRJpFrP_595qm-i78rkEW1ze_vRas\",\"x\":\"_aPIv0IKlu4mKCraN_YVs5xKeRHSPq8UBpHwz8GqFsE\",\"y\":\"WK-gDbHs0TBcFeYXIWAUnbOtj4Nq8EATxVp2SNM4uX8\",\"alg\":\"ES256\"}\n"

    private TestECSignatureGeneratorConfiguration testECSigGenConfig = new TestECSignatureGeneratorConfiguration(primaryKey)
    private TestECSignatureGeneratorConfigurationWithKid testECSigGenConfigWithKid = new TestECSignatureGeneratorConfigurationWithKid(primaryKey)

    void "by default doesn't add kid to the jwt headers"() {
        given:
        ECSignatureGenerator generator = new ECSignatureGenerator(testECSigGenConfig)

        when:
        Map<String, String> testClaims = new HashMap<>()
        testClaims.put("supersonic", "true")
        SignedJWT signedJWT = generator.sign(JWTClaimsSet.parse(testClaims))

        then:
        String headerKid = signedJWT.getHeader().toJSONObject().get("kid")
        headerKid == null
    }

    void "can optionally be extended to include the kid in the jwt headers"() {
        given:
        ECSignatureGenerator generator = new ECSignatureGenerator(testECSigGenConfigWithKid)

        when:
        Map<String, String> testClaims = new HashMap<>()
        testClaims.put("supersonic", "true")
        SignedJWT signedJWT = generator.sign(JWTClaimsSet.parse(testClaims))

        then:
        String headerKid = signedJWT.getHeader().toJSONObject().get("kid")
        headerKid == testECSigGenConfigWithKid.getKid()
    }
}
