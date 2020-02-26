package io.micronaut.security.oauth2.endpoint.authorization.state;

import java.net.URI;

/**
 * Represents a mutable state object.
 *
 * @author James Kleeh
 * @since 1.3.2
 */
public interface MutableState extends State {

    /**
     * @param originalUri The original uri
     */
    void setOriginalUri(URI originalUri);

    /**
     * @param nonce The nonce
     */
    void setNonce(String nonce);

    /**
     * @param redirectUri The redirect URI used in the authorization request
     */
    void setRedirectUri(URI redirectUri);
}
