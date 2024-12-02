package io.micronaut.security.oauth2.client

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class IdTokenClaimsValidatorSpec extends ApplicationContextSpecification {

    void "by default no bean of type IdTokenClaimsValidator exists"() {
        expect:
        !applicationContext.containsBean(IdTokenClaimsValidator)
    }

    @Unroll
    void "issuer IdTokenClaimsValidator"(String configIss, String iss) {
        given:
        def oauthClientConfiguration = new OauthClientConfigurationProperties("oci");
        def openId = new OauthClientConfigurationProperties.OpenIdClientConfigurationProperties("oci");
        openId.setIssuer(new URL(configIss))
        oauthClientConfiguration.setOpenid(openId)
        List<OauthClientConfiguration> l = List.of(oauthClientConfiguration)
        IdTokenClaimsValidator claimsValidator = new IdTokenClaimsValidator(List.of(l))

        when:
        Optional<Boolean> validation = claimsValidator.matchesIssuer(openId, iss)

        then:
        validation.isPresent()
        validation.get() == true

        where:
        configIss | iss
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com/"
        "https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com" | "https://identity.oraclecloud.com"
        "https://identity.oraclecloud.com" | "https://identity.oraclecloud.com"
    }
}
