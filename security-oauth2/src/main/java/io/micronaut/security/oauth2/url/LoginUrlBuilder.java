package io.micronaut.security.oauth2.url;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;

@Singleton
public class LoginUrlBuilder implements UrlBuilder {

    private final String urlTemplate;
    private final HostResolver hostResolver;

    LoginUrlBuilder(HostResolver hostResolver,
                    OauthConfigurationProperties oauthConfigurationProperties) {
        this.hostResolver = hostResolver;
        this.urlTemplate = oauthConfigurationProperties.getLoginUri();
    }

    @Override
    public String build(HttpRequest originating, String providerName) {
        return UriBuilder.of(hostResolver.resolve(originating))
                .path(getPath(providerName))
                .build()
                .toString();
    }

    @Override
    public String getPath(String providerName) {
        Map<String, Object> uriParams = new HashMap<>(1);
        uriParams.put("provider", providerName);
        return UriTemplate.of(urlTemplate).expand(uriParams);
    }
}
