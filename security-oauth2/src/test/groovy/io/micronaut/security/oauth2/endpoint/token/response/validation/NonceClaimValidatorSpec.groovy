package io.micronaut.security.oauth2.endpoint.token.response.validation

import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceFactory
import io.micronaut.security.oauth2.endpoint.nonce.NonceFactory
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class NonceClaimValidatorSpec extends ApplicationContextSpecification {

    void "NonceClaimsValidator bean exists by default"() {
        expect:
        applicationContext.containsBean(NonceClaimValidator)
    }

    @Unroll("with nonce persistence: persisted nonce #persistedNonce and nonce claim #nonceClaim => #expected")
    void "when a nonce factory is present the persisted nonce must be present and match the nonce claim"(String persistedNonce,
                                                                                                          String nonceClaim,
                                                                                                          boolean expected) {
        given:
        NonceFactory nonceFactory = new DefaultNonceFactory(Stub(NoncePersistence))
        NonceClaimValidator validator = new NonceClaimValidator(nonceFactory)

        expect:
        expected == validator.validate(claims(nonceClaim), clientConfiguration(), providerMetadata(), persistedNonce)

        where:
        persistedNonce | nonceClaim || expected
        'abc'          | 'abc'      || true
        'abc'          | 'xyz'      || false
        'abc'          | null       || false
        null           | 'abc'      || false
        null           | null       || false
    }

    @Unroll("without nonce persistence: persisted nonce #persistedNonce and nonce claim #nonceClaim => #expected")
    void "when no nonce factory is present validation passes only if no nonce was persisted and the ID token carries no nonce claim"(String persistedNonce,
                                                                                                                                       String nonceClaim,
                                                                                                                                       boolean expected) {
        given:
        NonceClaimValidator validator = new NonceClaimValidator(null)

        expect:
        expected == validator.validate(claims(nonceClaim), clientConfiguration(), providerMetadata(), persistedNonce)

        where:
        persistedNonce | nonceClaim || expected
        'abc'          | 'abc'      || true
        'abc'          | 'xyz'      || false
        'abc'          | null       || false
        null           | 'abc'      || false
        null           | null       || true
    }

    void "the NonceClaimValidator bean fails when the persisted nonce is missing because a nonce factory exists by default"() {
        given:
        NonceClaimValidator validator = applicationContext.getBean(NonceClaimValidator)

        expect:
        applicationContext.containsBean(NonceFactory)
        !validator.validate(claims(null), clientConfiguration(), providerMetadata(), null)
        validator.validate(claims('abc'), clientConfiguration(), providerMetadata(), 'abc')
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    void "the deprecated no-argument constructor behaves as if no nonce factory is present"() {
        given:
        NonceClaimValidator validator = new NonceClaimValidator()

        expect:
        validator.validate(claims(null), clientConfiguration(), providerMetadata(), null)
        validator.validate(claims('abc'), clientConfiguration(), providerMetadata(), 'abc')
        !validator.validate(claims('abc'), clientConfiguration(), providerMetadata(), null)
        !validator.validate(claims(null), clientConfiguration(), providerMetadata(), 'abc')
    }

    @Unroll("without a nonce sent: nonce factory present #nonceFactoryPresent and nonce claim #nonceClaim => #expected")
    void "a flow which never sends a nonce passes only if the ID token carries no nonce claim"(boolean nonceFactoryPresent,
                                                                                              String nonceClaim,
                                                                                              boolean expected) {
        given:
        NonceFactory nonceFactory = nonceFactoryPresent ? new DefaultNonceFactory(Stub(NoncePersistence)) : null
        NonceClaimValidator validator = new NonceClaimValidator(nonceFactory)

        expect:
        expected == validator.validateWithoutNonce(claims(nonceClaim), clientConfiguration(), providerMetadata())

        where:
        nonceFactoryPresent | nonceClaim || expected
        true                | null       || true
        true                | 'abc'      || false
        false               | null       || true
        false               | 'abc'      || false
    }

    private static OpenIdClaims claims(String nonceClaim) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer('https://issuer.example.com')
                .subject('subject')
                .audience('CLIENTID')
        if (nonceClaim != null) {
            builder.claim(OpenIdClaims.CLAIMS_NONCE, nonceClaim)
        }
        new JWTOpenIdClaims(builder.build())
    }

    private OauthClientConfiguration clientConfiguration() {
        Stub(OauthClientConfiguration) {
            getClientId() >> 'CLIENTID'
            getName() >> 'provider'
        }
    }

    private OpenIdProviderMetadata providerMetadata() {
        Stub(OpenIdProviderMetadata)
    }
}
