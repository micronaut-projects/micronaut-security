package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public abstract class AbstractEndSessionRequest implements EndSessionRequest {

    @Nullable
    protected final EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder;
    protected final OauthClientConfiguration clientConfiguration;
    protected final OpenIdProviderMetadata providerMetadata;

    public AbstractEndSessionRequest(@Nullable EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder,
                                     OauthClientConfiguration clientConfiguration,
                                     OpenIdProviderMetadata providerMetadata) {
        this.endSessionCallbackUrlBuilder = endSessionCallbackUrlBuilder;
        this.clientConfiguration = clientConfiguration;
        this.providerMetadata = providerMetadata;
    }

    @Nullable
    @Override
    public String getUrl(HttpRequest originating,
                         Authentication authentication) {
        Map<String, Map> parameters = new HashMap<>(1);
        parameters.put("parameters", getArguments(originating, authentication));

        return getTemplate().expand(parameters);
    }

    protected UriTemplate getTemplate() {
        return UriTemplate.of(getUrl()).nest("{?parameters*}");
    }

    protected abstract String getUrl();

    protected abstract Map<String, Object> getArguments(HttpRequest originating, Authentication authentication);

    protected Optional<String> getRedirectUri(HttpRequest originating) {
        return Optional.ofNullable(endSessionCallbackUrlBuilder)
                .map(builder -> builder.build(originating, null));
    }
}
