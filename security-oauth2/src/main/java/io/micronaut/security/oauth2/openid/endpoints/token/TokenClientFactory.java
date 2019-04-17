/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.endpoints.token;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Named;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Creates an Oaut2h token endpoint RxHttpClient.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Factory
public class TokenClientFactory {

    private static final Logger LOG = LoggerFactory.getLogger(TokenClientFactory.class);

    private final OpenIdEndpoints openIdEndpoints;

    /**
     *
     * @param openIdEndpoints Open ID endpoints
     */
    public TokenClientFactory(OpenIdEndpoints openIdEndpoints) {
        this.openIdEndpoints = openIdEndpoints;
    }

    /**
     *
     * @param context Bean Context
     * @param configuration HttpClient configuration
     * @return An RxHttpClient bean named oauth2tokenendpoint using the Token URL
     */
    @Named("oauth2tokenendpoint")
    @Bean(preDestroy = "close")
    public RxHttpClient tokenClient(@Nonnull BeanContext context, @Nullable HttpClientConfiguration configuration) {
        URL url;
        try {
            url = new URL(openIdEndpoints.getToken());
        } catch (MalformedURLException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Malformed URL exception with token endpoint: {}", openIdEndpoints.getToken(), e);
            }
            return null;
        }
        return context.createBean(RxHttpClient.class, url, configuration);
    }
}
