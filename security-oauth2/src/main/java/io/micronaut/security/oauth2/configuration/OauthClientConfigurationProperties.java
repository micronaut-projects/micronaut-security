package io.micronaut.security.oauth2.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.endpoints.*;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.endpoint.authorization.request.Display;
import io.micronaut.security.oauth2.endpoint.authorization.request.OpenIdScope;
import io.micronaut.security.oauth2.endpoint.authorization.request.Prompt;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Creates a bean of type {@link OauthClientConfiguration} for each micronaut.security.oauth2.clients during startup of the bean context.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
@Context
@EachProperty(OauthConfigurationProperties.PREFIX + ".clients")
public class OauthClientConfigurationProperties implements OauthClientConfiguration {

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private List<String> DEFAULT_SCOPES = new ArrayList<>();

    private final String name;
    private String clientId;
    private String clientSecret;
    private List<String> scopes;
    private boolean enabled = DEFAULT_ENABLED;
    private GrantType grantType = GrantType.AUTHORIZATION_CODE;
    private AuthorizationEndpointConfigurationProperties authorization;
    private TokenEndpointConfigurationProperties token;
    private OpenIdClientConfigurationProperties openid;

    public OauthClientConfigurationProperties(@Parameter String name) {
        this.name = name;
    }

    /**
     * OAuth 2.0 Application Client ID.
     * @param clientId The application's Client ID.
     */
    public void setClientId(@Nonnull String clientId) {
        this.clientId = clientId;
    }

    /**
     * OAuth 2.0 Application Client Secret. Optional.
     * @param clientSecret The application's Client Secret.
     */
    public void setClientSecret(@Nullable String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     *
     * @return the application's Client identifier
     */
    @Nonnull
    @Override
    public String getClientId() {
        return clientId;
    }

    /**
     *
     @return the application's Client secret
     */
    @Nullable
    @Override
    public String getClientSecret() {
        return clientSecret;
    }


    /**
     * @return true if you want to enable the {@link OauthClientConfiguration}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link OauthClientConfiguration} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Nonnull
    @Override
    public List<String> getScopes() {
        return scopes == null ? DEFAULT_SCOPES : scopes;
    }

    /**
     * Sets the scopes to request.
     *
     * @param scopes
     */
    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    @Nonnull
    @Override
    public String getName() {
        return name;
    }


    @Nonnull
    @Override
    public GrantType getGrantType() {
        return grantType;
    }

    /**
     * OAuth 2.0 grant type. Default value (authorization_code).
     *
     * @param grantType The grant type
     */
    public void setGrantType(@Nonnull GrantType grantType) {
        this.grantType = grantType;
    }

    public Optional<SecureEndpointConfiguration> getToken() {
        return Optional.ofNullable(token);
    }

    public void setToken(TokenEndpointConfigurationProperties token) {
        this.token = token;
    }

    public Optional<EndpointConfiguration> getAuthorization() {
        return Optional.ofNullable(authorization);
    }

    public void setAuthorization(AuthorizationEndpointConfigurationProperties authorization) {
        this.authorization = authorization;
    }

    /**
     * @return The open id configuration
     */
    public Optional<OpenIdClientConfiguration> getOpenid() {
        return Optional.ofNullable(openid);
    }

    /**
     * The open id configuration.
     *
     * @param openid The open id configuration
     */
    public void setOpenid(OpenIdClientConfigurationProperties openid) {
        this.openid = openid;
        this.DEFAULT_SCOPES = Arrays.asList(OpenIdScope.OPENID.toString(),
                OpenIdScope.EMAIL.toString(),
                OpenIdScope.PROFILE.toString());
    }

    @ConfigurationProperties("authorization")
    public static class AuthorizationEndpointConfigurationProperties extends DefaultEndpointConfiguration {

    }

    @ConfigurationProperties("token")
    public static class TokenEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration {

    }

    @ConfigurationProperties("openid")
    public static class OpenIdClientConfigurationProperties implements OpenIdClientConfiguration {

        private static final String DEFAULT_CONFIG_PATH = "/.well-known/openid-configuration";
        private final String name;

        private URL issuer;
        private String configurationPath = DEFAULT_CONFIG_PATH;
        private String jwksUri;
        private IntrospectionEndpointConfigurationProperties introspection;
        private RevocationEndpointConfigurationProperties revocation;
        private RegistrationEndpointConfigurationProperties registration;
        private UserInfoEndpointConfigurationProperties userInfo;
        private AuthorizationEndpointConfigurationProperties authorization;
        private TokenEndpointConfigurationProperties token;

        OpenIdClientConfigurationProperties(@Parameter String name) {
            this.name = name;
        }

        @Nonnull
        @Override
        public String getName() {
            return name;
        }

        public Optional<URL> getIssuer() {
            return Optional.ofNullable(issuer);
        }

        /**
         * URL using the https scheme with no query or fragment component that the Open ID provider asserts as its issuer identifier.
         *
         * @param issuer The issuer
         */
        public void setIssuer(@Nullable URL issuer) {
            this.issuer = issuer;
        }

        /**
         * @return The configuration path
         */
        @Override
        @Nonnull
        public String getConfigurationPath() {
            return configurationPath;
        }

        /**
         * The configuration path to discover openid configuration. Default ({@value DEFAULT_CONFIG_PATH}).
         *
         * @param configurationPath The configuration path
         */
        public void setConfigurationPath(@Nonnull String configurationPath) {
            this.configurationPath = configurationPath;
        }

        /**
         * @return The JWKS signature configuration
         */
        @Override
        public Optional<String> getJwksUri() {
            return Optional.ofNullable(jwksUri);
        }

        /**
         * The JWKS signature URI.
         *
         * @param jwksUri The signature uri
         */
        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        public Optional<SecureEndpointConfiguration> getIntrospection() {
            return Optional.ofNullable(introspection);
        }

        public void setIntrospection(IntrospectionEndpointConfigurationProperties introspection) {
            this.introspection = introspection;
        }

        public Optional<SecureEndpointConfiguration> getRevocation() {
            return Optional.ofNullable(revocation);
        }

        public void setRevocation(RevocationEndpointConfigurationProperties revocation) {
            this.revocation = revocation;
        }

        @Override
        public Optional<EndpointConfiguration> getRegistration() {
            return Optional.ofNullable(registration);
        }

        public void setRegistration(RegistrationEndpointConfigurationProperties registration) {
            this.registration = registration;
        }

        @Override
        public Optional<EndpointConfiguration> getUserInfo() {
            return Optional.ofNullable(userInfo);
        }

        public void setUserInfo(UserInfoEndpointConfigurationProperties userInfo) {
            this.userInfo = userInfo;
        }

        public Optional<AuthorizationEndpointConfiguration> getAuthorization() {
            return Optional.ofNullable(authorization);
        }

        public void setAuthorization(AuthorizationEndpointConfigurationProperties authorization) {
            this.authorization = authorization;
        }

        public Optional<TokenEndpointConfiguration> getToken() {
            return Optional.ofNullable(token);
        }

        public void setToken(TokenEndpointConfigurationProperties token) {
            this.token = token;
        }

        @ConfigurationProperties("introspection")
        public static class IntrospectionEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements IntrospectionEndpointConfiguration { }

        @ConfigurationProperties("revocation")
        public static class RevocationEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements RevocationEndpointConfiguration { }

        @ConfigurationProperties("registration")
        public static class RegistrationEndpointConfigurationProperties extends DefaultEndpointConfiguration {}

        @ConfigurationProperties("user-info")
        public static class UserInfoEndpointConfigurationProperties extends DefaultEndpointConfiguration { }

        @ConfigurationProperties("authorization")
        public static class AuthorizationEndpointConfigurationProperties extends DefaultEndpointConfiguration implements AuthorizationEndpointConfiguration {

            private ResponseType responseType = ResponseType.CODE;
            private String responseMode;
            private Display display;
            private Prompt prompt;
            private Integer maxAge;
            private List<String> uiLocales;
            private List<String>  acrValues;

            @Nonnull
            @Override
            public ResponseType getResponseType() {
                return responseType;
            }

            /**
             * Value that determines the authorization processing flow to be used. Default value (code). See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param responseType The response type
             */
            public void setResponseType(@Nonnull ResponseType responseType) {
                this.responseType = responseType;
            }

            @Override
            public Optional<String> getResponseMode() {
                return Optional.ofNullable(responseMode);
            }

            /**
             * Mechanism to be used for returning Authorization Response parameters from the Authorization Endpoint. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             * @param responseMode The response mode
             */
            public void setResponseMode(@Nullable String responseMode) {
                this.responseMode = responseMode;
            }

            @Override
            public Optional<Display> getDisplay() {
                return Optional.ofNullable(display);
            }

            /**
             * Controls how the authentication interface is displayed. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param display The display
             */
            public void setDisplay(@Nullable Display display) {
                this.display = display;
            }

            @Override
            public Optional<Prompt> getPrompt() {
                return Optional.ofNullable(prompt);
            }

            /**
             * Controls how the authentication server prompts the user. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param prompt The prompt type
             */
            public void setPrompt(@Nullable Prompt prompt) {
                this.prompt = prompt;
            }

            @Override
            public Optional<Integer> getMaxAge() {
                return Optional.ofNullable(maxAge);
            }

            /**
             * Maximum authentication age. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param maxAge Maximum authentication age.
             */
            public void setMaxAge(@Nullable Integer maxAge) {
                this.maxAge = maxAge;
            }

            @Override
            public Optional<List<String>> getUiLocales() {
                return Optional.ofNullable(uiLocales);
            }

            /**
             * Preferred locales for authentication. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param uiLocales Preferred locales
             */
            public void setUiLocales(@Nullable List<String> uiLocales) {
                this.uiLocales = uiLocales;
            }

            @Override
            public Optional<List<String>> getAcrValues() {
                return Optional.ofNullable(acrValues);
            }

            /**
             * Authentication class reference values. See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
             *
             * @param acrValues Authentication class reference values
             */
            public void setAcrValues(@Nullable List<String>  acrValues) {
                this.acrValues = acrValues;
            }
        }

        @ConfigurationProperties("token")
        public static class TokenEndpointConfigurationProperties extends DefaultSecureEndpointConfiguration implements TokenEndpointConfiguration {

            /**
             * Default content type.
             */
            @SuppressWarnings("WeakerAccess")
            public static final MediaType DEFAULT_CONTENT_TYPE = MediaType.APPLICATION_FORM_URLENCODED_TYPE;

            private MediaType contentType = DEFAULT_CONTENT_TYPE;

            @Nonnull
            @Override
            public MediaType getContentType() {
                return this.contentType;
            }

            /**
             * The Content-Type used to communicate with the token endpoint. Default value (application/x-www-form-urlencoded).
             * @param contentType The Content-Type
             */
            public void setContentType(@Nonnull MediaType contentType) {
                this.contentType = contentType;
            }
        }
    }
}
