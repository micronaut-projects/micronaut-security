package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.Secondary;
import io.micronaut.http.MutableHttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;

/**
 * Use basic authentication to authorize call to introspection endpoint.
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
@Singleton
@Secondary
public class BasicIntrospectionEndpointAuthStrategy implements IntrospectionEndpointAuthStrategy {

    private static final Logger LOG = LoggerFactory.getLogger(BasicIntrospectionEndpointAuthStrategy.class);

    private final BearerTokenIntrospectionProperties.IntrospectionCredentials credentials;

    /**
     * @param introspectionProperties config with credentials to introspection endpoint. If either clientId or secret are not
     *                                provided, call will be done without authorization header.
     */
    public BasicIntrospectionEndpointAuthStrategy(BearerTokenIntrospectionProperties introspectionProperties) {
        this.credentials = introspectionProperties.getCredentials();
    }

    @Override
    public <T> MutableHttpRequest<T> authorizeRequest(MutableHttpRequest<T> request) {
        if (credentials.getClientId() == null || credentials.getClientSecret() == null) {
            LOG.debug("Introspection endpoint credentials are not provided");
            return request;
        }

        return request.basicAuth(credentials.getClientId(), credentials.getClientSecret());
    }
}
