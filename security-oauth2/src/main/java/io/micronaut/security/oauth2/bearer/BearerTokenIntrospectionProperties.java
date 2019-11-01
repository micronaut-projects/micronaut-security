package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static io.micronaut.security.oauth2.bearer.BearerTokenIntrospectionProperties.PREFIX;
import static io.micronaut.security.oauth2.bearer.ClientCredentialsTokenValidator.OAUTH_TOKEN_AUTHORIZATION_CONFIG;

/**
 * Default implementation of {@link TokenIntrospectionConfiguration}.
 *
 * @author svishnyakoff
 */
@ConfigurationProperties(PREFIX)
public class BearerTokenIntrospectionProperties implements TokenIntrospectionConfiguration{

    static final String PREFIX = OAUTH_TOKEN_AUTHORIZATION_CONFIG + ".introspection";

    private URL url;
    private String tokenParam = "token";
    private Map<String, String> tokenHintsParameters = Collections.emptyMap();
    private IntrospectionCredentials credentials = new IntrospectionCredentials();

    @Override
    public URL getUrl() {
        return this.url;
    }

    public void setUrl(URL url) {
        this.url = url;
    }

    @Override
    public Map<String, String> getTokenHintsParameters() {
        return this.tokenHintsParameters;
    }

    public void setTokenHintsParameters(Map<String, String> tokenHintsParameters) {
        this.tokenHintsParameters = Optional.ofNullable(tokenHintsParameters).orElse(Collections.emptyMap());
    }

    @Override
    public String getTokenParam() {
        return this.tokenParam;
    }

    public void setTokenParam(String tokenParam) {
        this.tokenParam = tokenParam;
    }

    public IntrospectionCredentials getCredentials() {
        return this.credentials;
    }

    public void setCredentials(IntrospectionCredentials credentials) {
        this.credentials = credentials;
    }

    @ConfigurationProperties("credentials")
    public static class IntrospectionCredentials {
        private String clientId;
        private String clientSecret;

        public String getClientId() {
            return this.clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return this.clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }
    }
}
