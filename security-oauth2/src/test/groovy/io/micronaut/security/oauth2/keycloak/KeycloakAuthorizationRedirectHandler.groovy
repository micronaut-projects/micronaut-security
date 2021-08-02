package io.micronaut.security.oauth2.keycloak

import io.micronaut.core.annotation.NonNull
import io.micronaut.security.oauth2.endpoint.authorization.request.DefaultAuthorizationRedirectHandler
import io.micronaut.security.testutils.TestContainersUtils

abstract class KeycloakAuthorizationRedirectHandler extends DefaultAuthorizationRedirectHandler {
    @Override
    protected String expandedUri(@NonNull String baseUrl, @NonNull Map<String, Object> queryParams) {
        String uri = super.expandedUri(baseUrl, queryParams)
        if (TestContainersUtils.isGebUsingTestContainers()) {
            uri = uri.replaceAll("localhost", TestContainersUtils.host)
        }
        uri
    }
}
