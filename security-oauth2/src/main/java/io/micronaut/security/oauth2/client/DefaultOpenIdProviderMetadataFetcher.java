/*
 * Copyright 2017-2021 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Default implementation of {@link OpenIdProviderMetadataFetcher}.
 * @author Sergio del Amo
 * @since 3.3.0
 */
public class DefaultOpenIdProviderMetadataFetcher implements OpenIdProviderMetadataFetcher {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdProviderMetadataFetcher.class);
    private final HttpClient client;
    private final ObjectMapper objectMapper;
    private final OpenIdClientConfiguration openIdClientConfiguration;

    public DefaultOpenIdProviderMetadataFetcher(OpenIdClientConfiguration openIdClientConfiguration,
                                                ObjectMapper objectMapper,
                                                @Client HttpClient client) {
        this.openIdClientConfiguration = openIdClientConfiguration;
        this.objectMapper = objectMapper;
        this.client = client;
    }

    @Override
    @NonNull
    public DefaultOpenIdProviderMetadata fetch() {
        return openIdClientConfiguration.getIssuer()
                .map(issuer -> {
                    try {
                        URL configurationUrl = new URL(issuer, StringUtils.prependUri(issuer.getPath(), openIdClientConfiguration.getConfigurationPath()));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Sending request for OpenID configuration for provider [{}] to URL [{}]", openIdClientConfiguration.getName(), configurationUrl);
                        }
                        //TODO this returns ReadTimeoutException - return issuerClient.toBlocking().retrieve(configurationUrl.toString(), DefaultOpenIdProviderMetadata.class);
                        String json = client.toBlocking().retrieve(configurationUrl.toString(), String.class);
                        return objectMapper.readValue(json, DefaultOpenIdProviderMetadata.class);

                    } catch (MalformedURLException e) {
                        throw new BeanInstantiationException("Failure parsing issuer URL " + issuer.toString(), e);
                    } catch (HttpClientResponseException e) {
                        throw new BeanInstantiationException("Failed to retrieve OpenID configuration for " + openIdClientConfiguration.getName(), e);

                    } catch (JsonProcessingException e) {
                        throw new BeanInstantiationException("JSON Processing Exception parsing issuer URL returned JSON " + issuer.toString(), e);
                    }
                }).orElse(new DefaultOpenIdProviderMetadata());
    }
}
