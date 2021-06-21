package io.micronaut.security.oauth2.keycloak

import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator
import io.micronaut.security.testutils.TestContainersUtils

abstract class KeycloakIssuerClaimValidator extends IssuerClaimValidator {
    @Override
    boolean validate(OpenIdClaims claims,
                     OauthClientConfiguration clientConfiguration,
                     OpenIdProviderMetadata providerMetadata) {
        claims.issuer ?
                claims.issuer == providerMetadata.issuer || claims.issuer == providerMetadata.issuer.replaceAll("localhost", TestContainersUtils.host) :
                false
    }
}
