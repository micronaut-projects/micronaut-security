package io.micronaut.security.oauth2.keycloak

import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.http.uri.UriBuilder
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint
import io.micronaut.security.testutils.TestContainersUtils
import javax.inject.Named

class KeycloakEndSessionEndpoint implements EndSessionEndpoint {

    public static final String PARAM_REDIRECT_URI = "redirect_uri"
    private final OpenIdProviderMetadata openIdProviderMetadata
    private final EndSessionConfiguration endSessionConfiguration
    private final HttpHostResolver httpHostResolver

    KeycloakEndSessionEndpoint(OpenIdProviderMetadata openIdProviderMetadata,
                               EndSessionConfiguration endSessionConfiguration,
                               HttpHostResolver httpHostResolver) {
        this.openIdProviderMetadata = openIdProviderMetadata
        this.endSessionConfiguration = endSessionConfiguration
        this.httpHostResolver = httpHostResolver
    }

    @Nullable
    @Override
    String getUrl(HttpRequest originating, Authentication authentication) {
        String redirectUri = this.httpHostResolver.resolve(originating) + endSessionConfiguration.getRedirectUri();
        if (TestContainersUtils.isGebUsingTestContainers()) {
            redirectUri = redirectUri.replaceAll("localhost", TestContainersUtils.host)
        }
        Optional<String> endsessionOptional = getEndSessionEndpoint()
        if (endsessionOptional.isPresent()) {
            String endsessionUri = endsessionOptional.get()
            String uri = UriBuilder.of(endsessionUri).queryParam(PARAM_REDIRECT_URI, redirectUri)
                    .build()
                    .toString()
            System.out.println(uri)
            return uri
        }
        return null
    }

    private Optional<String> getEndSessionEndpoint() {
        if (openIdProviderMetadata.getEndSessionEndpoint() == null) {
            return Optional.empty()
        }
        String uri = openIdProviderMetadata.getEndSessionEndpoint()
        if (TestContainersUtils.isGebUsingTestContainers()) {
            uri = uri.replaceAll("localhost", TestContainersUtils.host)
        }
        Optional.of(uri)
    }
}
