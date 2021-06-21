package io.micronaut.security.oauth2.keycloak

import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.DefaultProviderResolver
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.testutils.TestContainersUtils
import io.micronaut.security.token.jwt.generator.claims.JwtClaims

abstract class KeycloakProviderResolver extends DefaultProviderResolver {
    KeycloakProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
        super(openIdClientConfigurations)
    }

    @Override
    protected Optional<String> openIdClientNameWhichMatchesIssClaim(Authentication authentication) {
        Object issuer = authentication.getAttributes().get(JwtClaims.ISSUER)
        if (issuer == null) {
            return Optional.empty()
        }
       Optional<String> result = openIdClientNameWhichMatchesIssuer(issuer.toString())
        return result.isPresent() ?
                result : openIdClientNameWhichMatchesIssuer(issuer.toString().replaceAll(TestContainersUtils.host, "localhost"))
    }
}
