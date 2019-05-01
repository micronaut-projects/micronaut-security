package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Prototype;
import io.micronaut.core.convert.value.ConvertibleMultiValues;
import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.authorization.response.*;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequestBuilder;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRedirectUrlBuilder;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;
import org.reactivestreams.Publisher;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Prototype
public class DefaultOpenIdClient implements OpenIdClient {

    private final OauthClientConfiguration clientConfiguration;
    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final AuthorizationRequestBuilder authorizationRequestBuilder;
    private final AuthorizationRedirectUrlBuilder redirectUrlBuilder;
    private final OpenIdAuthorizationResponseHandler authorizationResponseHandler;
    private final SecureEndpoint tokenEndpoint;
    private final BeanContext beanContext;

    DefaultOpenIdClient(@Parameter OauthClientConfiguration clientConfiguration,
                        @Parameter OpenIdProviderMetadata openIdProviderMetadata,
                        AuthorizationRequestBuilder authorizationRequestBuilder,
                        AuthorizationRedirectUrlBuilder redirectUrlBuilder,
                        OpenIdAuthorizationResponseHandler authorizationResponseHandler,
                        BeanContext beanContext) {
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.authorizationRequestBuilder = authorizationRequestBuilder;
        this.redirectUrlBuilder = redirectUrlBuilder;
        this.authorizationResponseHandler = authorizationResponseHandler;
        this.beanContext = beanContext;
        this.tokenEndpoint = getTokenEndpoint(openIdProviderMetadata);
    }

    @Override
    public String getName() {
        return clientConfiguration.getName();
    }

    @Override
    public HttpResponse authorizationRedirect(HttpRequest originating) {
        AuthorizationRequest authorizationRequest = authorizationRequestBuilder.buildRequest(originating, clientConfiguration);
        return HttpResponse.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION,
                        redirectUrlBuilder.buildUrl(authorizationRequest, openIdProviderMetadata.getAuthorizationEndpoint()));
    }

    @Override
    public Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request) {

        ConvertibleMultiValues<String> responseData = request.getBody()
                .map(body -> {
                    MutableConvertibleMultiValuesMap<String> map = new MutableConvertibleMultiValuesMap<>();
                    body.forEach((key, value) -> map.add(key, value.toString()));
                    return (ConvertibleMultiValues<String>) map;
                }).orElseGet(request::getParameters);

        if (isErrorCallback(responseData)) {
            AuthorizationErrorResponse callback = beanContext.createBean(AuthorizationErrorResponse.class, request);
            throw new AuthorizationErrorResponseException(callback);
        } else {
            AuthorizationResponse authorizationResponse = beanContext.createBean(AuthorizationResponse.class, request);
            return authorizationResponseHandler.handle(authorizationResponse,
                    clientConfiguration,
                    openIdProviderMetadata,
                    tokenEndpoint);
        }
    }

    protected boolean isErrorCallback(ConvertibleMultiValues<String> responseData) {
        return responseData.contains("error");
    }

    protected SecureEndpoint getTokenEndpoint(OpenIdProviderMetadata openIdProviderMetadata) {
        List<String> authMethodsSupported = openIdProviderMetadata.getTokenEndpointAuthMethodsSupported();
        List<AuthenticationMethod> authenticationMethods = null;
        if (authMethodsSupported != null) {
            authenticationMethods = authMethodsSupported.stream()
                    .map(String::toUpperCase)
                    .map(AuthenticationMethod::valueOf)
                    .collect(Collectors.toList());
        }
        return new DefaultSecureEndpoint(openIdProviderMetadata.getTokenEndpoint(), authenticationMethods);
    }
}
