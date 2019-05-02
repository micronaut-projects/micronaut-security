package io.micronaut.security.oauth2.configuration.endpoints;

import java.util.Optional;

/**
 * Default implementation of {@link EndpointConfiguration}.
 * @author James Kleeh
 * @since 1.0.0
 */
public class DefaultEndpointConfiguration implements EndpointConfiguration {

    private String url;

    @Override
    public Optional<String> getUrl() {
        return Optional.ofNullable(url);
    }

    /**
     *
     * @param url endpoint's url.
     */
    public void setUrl(String url) {
        this.url = url;
    }
}
