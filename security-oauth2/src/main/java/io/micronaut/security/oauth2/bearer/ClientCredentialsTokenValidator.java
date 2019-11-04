package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.IntrospectionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

/**
 * Token validator that uses OAuth 2.0 Token Introspection endpoint to validate token and authorize access.
 *
 * @author svishnyakoff
 * @see <a href="https://tools.ietf.org/html/rfc7662">rfc7662</a>
 */
@Singleton
@Internal
public class ClientCredentialsTokenValidator implements TokenValidator {

    static final String OAUTH_TOKEN_AUTHORIZATION_CONFIG = "micronaut.security.token.oauth2.bearer";

    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsTokenValidator.class);

    private final OauthClientConfiguration clientConfiguration;
    private final RxHttpClient oauthIntrospectionClient;
    private final List<TokenIntrospectionHandler> introspectionHandlers;
    private final String introspectionUrl;
    private final AuthenticationMethod authMethod;
    private final IntrospectionEndpointConfiguration introspectionConfiguration;

    /**
     * @param oauthClientConfigurations   oauth client configuration list. One configuration with CLIENT CREDENTIALS grant
     *                                    type is required in order this validator was operational
     * @param introspectedTokenValidators list of handlers that will proceed token introspection metadata.
     * @param beanContext                 bean context
     */
    @Inject
    public ClientCredentialsTokenValidator(List<TokenIntrospectionHandler> introspectedTokenValidators,
                                           List<OauthClientConfiguration> oauthClientConfigurations,
                                           BeanContext beanContext) {

        this(introspectedTokenValidators, getClientCredentialsConfiguration(oauthClientConfigurations),
             beanContext.createBean(RxHttpClient.class, getIntrospectionUrl(oauthClientConfigurations)));
    }

    public ClientCredentialsTokenValidator(List<TokenIntrospectionHandler> introspectedTokenValidators,
                                           OauthClientConfiguration oauthClientConfigurations,
                                           RxHttpClient httpClient) {
        this.oauthIntrospectionClient = httpClient;
        this.introspectionHandlers = introspectedTokenValidators;
        this.clientConfiguration = oauthClientConfigurations;
        this.introspectionUrl = clientConfiguration.getIntrospection().flatMap(EndpointConfiguration::getUrl).get();
        this.authMethod = clientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getAuthMethod).get();
        this.introspectionConfiguration = clientConfiguration.getIntrospection().get();
    }

    @Override
    public Publisher<Authentication> validateToken(String token) {

        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Bearer token cannot be null or empty");
        }

        MutableHttpRequest<String> request = HttpRequest
                .POST(introspectionUrl, tokenIntrospectionRequestBody(token))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        secureRequest(request);

        return oauthIntrospectionClient.exchange(request, Argument.of(Map.class, String.class, Object.class)).flatMap(response -> {
            if (response.status() == HttpStatus.UNAUTHORIZED) {
                LOG.error("Authorization service requires valid credentials to call introspection endpoint");
                return Flowable.empty();
            }
            else if (response.status() != HttpStatus.OK) {
                LOG.error("Request to introspection endpoint failed with: {}" , response.getStatus().getCode());
                return Flowable.empty();
            }

            try {
                Map<String, Object> introspectionMetadata = (Map<String, Object>) response.body();

                if (introspectionMetadata == null) {
                    LOG.error("Introspection endpoint return empty body. Valid json is expected.");
                    return Flowable.empty();
                }

                Optional<IntrospectedToken> activeToken = introspectionHandlers.stream()
                        .map(validator -> validator.handle(introspectionMetadata))
                        .filter(IntrospectedToken::isActive)
                        .findFirst();

                return activeToken.map(Flowable::just).orElse(Flowable.empty());
            }
            catch (Exception e) {
                LOG.error("Token introspection url must return valid json response");
                return Flowable.empty();
            }
        });
    }

    private <T> MutableHttpRequest<T> secureRequest(MutableHttpRequest<T> request) {
        if (authMethod == AuthenticationMethod.CLIENT_SECRET_BASIC) {
            LOG.debug("Adding basic authorization to introspection request");
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        }

        return request;
    }

    private String tokenIntrospectionRequestBody(String token) {
        String tokenParam = introspectionConfiguration.getTokenParam() + "=" + token;
        StringJoiner joiner = new StringJoiner("&");
        joiner.add(tokenParam);

        introspectionConfiguration.getTokenHintsParameters().entrySet().stream()
                .map(entry -> entry.getKey()+ "=" + entry.getValue())
                .forEach(joiner::add);

        return joiner.toString();
    }

    private static OauthClientConfiguration getClientCredentialsConfiguration(List<OauthClientConfiguration> clientConfigurations) {
        return clientConfigurations.stream()
                .filter(conf -> conf.getGrantType() == GrantType.CLIENT_CREDENTIALS)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Oauth client configuration with grant type CLIENT CREDENTIALS is required"));
    }

    private static String getIntrospectionUrl(List<OauthClientConfiguration> clientConfigurations) {
        return getClientCredentialsConfiguration(clientConfigurations)
                .getIntrospection()
                .get()
                .getUrl()
                .orElseThrow(() -> new RuntimeException("Introspection url is not provided"));
    }
}
