package io.micronaut.security.oauth2.bearer;

import java.util.Map;

/**
 * Handler responsible for processing token introspection metadata.
 *
 * While token introspection endpoint and it's response are standardized in scope of
 * <a href="https://tools.ietf.org/html/rfc7662">rfc7662<a/> there are known <a href="https://stackoverflow.com/questions/12296017/how-to-validate-an-oauth-2-0-access-token-for-a-resource-server">custom solutions</a>
 * that does not conform the defined RFC or may be were introduced before RFC is published.
 *
 * Developers can implement this interface if they need to support custom introspection response.
 */
public interface TokenIntrospectionHandler {

    /**
     * Takes introspection metadata as a map and produces introspection token
     *
     * @param tokenIntrospection introspection metadata
     * @return either valid or invalid introspection token.
     */
    IntrospectedToken handle(Map<String, Object> tokenIntrospection);
}
