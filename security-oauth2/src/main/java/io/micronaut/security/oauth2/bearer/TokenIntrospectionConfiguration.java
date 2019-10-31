package io.micronaut.security.oauth2.bearer;

import java.net.URL;
import java.util.Map;

/**
 * Configuration that contains information about oauth2 introspection endpoint and how to interact with it.
 *
 * @author svishnyakoff
 */
public interface TokenIntrospectionConfiguration {

    /**
     * @return URL of oauth2 introspection endpoint. The endpoint is usually located in authorization service and must
     * provided information about validity of given oauth2 token.
     */
    URL getUrl();

    /**
     * @return Additional parameters that will be passed in call to introspection endpoint.
     */
    Map<String, String> getTokenHintsParameters();

    /**
     * @return Name of the token parameter that is used during the call to token introspection endpoint.
     * Default name if not provided "token"
     */
    String getTokenParam();
}
