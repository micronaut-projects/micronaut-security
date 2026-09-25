package io.micronaut.security.oauth2.endpoint.nonce

import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.validation.NonceClaimValidator
import io.micronaut.security.testutils.ApplicationContextSpecification

class NonceDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.openid.nonce.enabled': false
        ]
    }

    void "micronaut.security.oauth2.openid.nonce.enabled: false disables nonce related beans"() {
        expect:
        !applicationContext.containsBean(NoncePersistence)
        !applicationContext.containsBean(NonceFactory)
        !applicationContext.containsBean(NonceConfiguration)
    }

    void "when the nonce is disabled the NonceClaimValidator bean still exists and passes when neither a persisted nonce nor a nonce claim exists"() {
        given:
        NonceClaimValidator validator = applicationContext.getBean(NonceClaimValidator)
        OauthClientConfiguration clientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> 'CLIENTID'
        }
        OpenIdProviderMetadata providerMetadata = Stub(OpenIdProviderMetadata)
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer('https://issuer.example.com')
                .subject('subject')
                .audience('CLIENTID')
        OpenIdClaims claimsWithoutNonce = new JWTOpenIdClaims(builder.build())
        OpenIdClaims claimsWithNonce = new JWTOpenIdClaims(builder.claim(OpenIdClaims.CLAIMS_NONCE, 'abc').build())

        expect:
        validator.validate(claimsWithoutNonce, clientConfiguration, providerMetadata, null)
        !validator.validate(claimsWithNonce, clientConfiguration, providerMetadata, null)
    }
}
