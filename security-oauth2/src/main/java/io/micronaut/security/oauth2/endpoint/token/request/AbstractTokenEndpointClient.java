package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.BeanContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.AuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import org.reactivestreams.Publisher;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public abstract class AbstractTokenEndpointClient<T extends TokenResponse> implements TokenEndpointClient<T>  {

    private final BeanContext beanContext;
    private final RxHttpClient defaultTokenClient;
    private final ConcurrentHashMap<String, RxHttpClient> tokenClients = new ConcurrentHashMap<>();

    public AbstractTokenEndpointClient(BeanContext beanContext,
                                       HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.defaultTokenClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultClientConfiguration);
    }

    @Nonnull
    @Override
    public Publisher<T> sendRequest(AuthorizationResponse authorizationResponse,
                                    OauthClientConfiguration clientConfiguration,
                                    SecureEndpoint tokenEndpoint) {
        AuthorizationCodeGrant authorizationCodeGrant = createBody(authorizationResponse, clientConfiguration);
        MediaType mediaType = getMediaType(clientConfiguration);

        MutableHttpRequest<AuthorizationCodeGrant> request = HttpRequest.POST(tokenEndpoint.getUrl(), authorizationCodeGrant)
                .contentType(mediaType);

        secureRequest(request, clientConfiguration, tokenEndpoint);

        return doSend(request, clientConfiguration);
    }

    abstract protected Publisher<T> doSend(MutableHttpRequest<AuthorizationCodeGrant> request,
                                           OauthClientConfiguration clientConfiguration);

    abstract protected MediaType getMediaType(OauthClientConfiguration clientConfiguration);
    /**
     *
     * @param request Token endpoint Request
     * @return a HTTP Request to the Token Endpoint with Authorization Code Grant payload.
     */
    protected void secureRequest(@Nonnull MutableHttpRequest<AuthorizationCodeGrant> request,
                                 OauthClientConfiguration clientConfiguration,
                                 SecureEndpoint tokenEndpoint) {
        List<AuthenticationMethod> authMethodsSupported = tokenEndpoint.getSupportedAuthenticationMethods().orElseGet(() ->
                Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC));

        if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_BASIC)) {
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        } else if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_POST)) {
            request.getBody().ifPresent(body -> body.setClientSecret(clientConfiguration.getClientSecret()));
        }
    }

    /**
     * @return A Authorization Code Grant
     */
    protected AuthorizationCodeGrant createBody(AuthorizationResponse authorizationResponse,
                                                OauthClientConfiguration clientConfiguration) {
        AuthorizationCodeGrant authorizationCodeGrant = new AuthorizationCodeGrant();
        authorizationCodeGrant.setCode(authorizationResponse.getCode());
        authorizationCodeGrant.setClientId(clientConfiguration.getClientId());
        return authorizationCodeGrant;
    }

    protected RxHttpClient getClient(String providerName) {
        return tokenClients.computeIfAbsent(providerName, (provider) -> {
            Optional<RxHttpClient> client = beanContext.findBean(RxHttpClient.class, Qualifiers.byName(provider));
            return client.orElse(defaultTokenClient);
        });
    }
}
