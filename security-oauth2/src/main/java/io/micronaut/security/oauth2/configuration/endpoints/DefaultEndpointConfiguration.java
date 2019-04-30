package io.micronaut.security.oauth2.configuration.endpoints;

import java.util.Optional;

public class DefaultEndpointConfiguration implements EndpointConfiguration {

    private String url;

    @Override
    public Optional<String> getUrl() {
        return Optional.ofNullable(url);
    }

    /**
     *
     * @param url Introspection endpoint's url.
     */
    public void setUrl(String url) {
        this.url = url;
    }
}
