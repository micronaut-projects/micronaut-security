package io.micronaut.security.oauth2.bearer;

import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.Authentication;
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
 * @see https://tools.ietf.org/html/rfc7662
 */
@Singleton
public class ClientCredentialsTokenValidator implements TokenValidator {

    static final String OAUTH_TOKEN_AUTHORIZATION_CONFIG = "micronaut.security.token.oauth2.bearer";

    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsTokenValidator.class);

    private final BearerTokenIntrospectionProperties introspectionConfiguration;
    private final RxHttpClient oauthIntrospectionClient;
    private final List<TokenIntrospectionHandler> introspectionHandlers;

    /**
     * @param introspectionConfiguration  configuration of oauth2 introspection endpoint.
     * @param introspectedTokenValidators list of handlers that will proceed token introspection metadata.
     */
    @Inject
    public ClientCredentialsTokenValidator(BearerTokenIntrospectionProperties introspectionConfiguration,
                                           List<TokenIntrospectionHandler> introspectedTokenValidators,
                                           @Client("${micronaut.security.token.oauth2.bearer.introspection.url}") RxHttpClient httpClient) {
        this.introspectionConfiguration = introspectionConfiguration;
        this.oauthIntrospectionClient = httpClient;
        this.introspectionHandlers = introspectedTokenValidators;
    }

    @Override
    public Publisher<Authentication> validateToken(String token) {

        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Bearer token cannot be null or empty");
        }

        HttpRequest<String> request = HttpRequest
                .POST("/", tokenIntrospectionRequestBody(token))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        return oauthIntrospectionClient.exchange(request, Argument.of(Map.class, String.class, Object.class)).flatMap(response -> {
            if (response.status() == HttpStatus.UNAUTHORIZED) {
                LOG.error("Authorization service requires valid credentials to call introspection endpoint");
                return Flowable.empty();
            }
            else if (response.status() != HttpStatus.OK) {
                LOG.error("Request to introspection endpoint failed with: {}" , response.getStatus().getCode());
                return Flowable.empty();
            }

            Map<String, Object> introspectionMetadata;
            try {
                introspectionMetadata = (Map<String, Object>) response.body();
            }
            catch (Exception e) {
                LOG.error("Token introspection url must return valid json response");
                return Flowable.empty();
            }

            Optional<IntrospectedToken> activeToken = introspectionHandlers.stream()
                    .map(validator -> validator.handle(introspectionMetadata))
                    .filter(IntrospectedToken::isActive)
                    .findFirst();

            return activeToken.map(Flowable::just).orElse(Flowable.empty());
        });
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
}
