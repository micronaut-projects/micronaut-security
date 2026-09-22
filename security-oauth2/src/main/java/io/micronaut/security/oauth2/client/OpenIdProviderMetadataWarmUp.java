/*
 * Copyright 2017-2025 original authors
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

import io.micronaut.context.BeanContext;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.BeanDefinition;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves every {@link DefaultOpenIdProviderMetadata} bean when the application starts, so that the OpenID configuration
 * is fetched before the first request and on a non event-loop thread.
 * <p>
 * A failure to fetch the metadata is logged and does not prevent the application from starting: the bean is created on a
 * later access, once the provider is reachable again.
 * </p>
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
@Singleton
final class OpenIdProviderMetadataWarmUp implements ApplicationEventListener<StartupEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdProviderMetadataWarmUp.class);

    private final BeanContext beanContext;

    OpenIdProviderMetadataWarmUp(BeanContext beanContext) {
        this.beanContext = beanContext;
    }

    @Override
    public void onApplicationEvent(StartupEvent event) {
        for (BeanDefinition<DefaultOpenIdProviderMetadata> definition : beanContext.getBeanDefinitions(DefaultOpenIdProviderMetadata.class)) {
            try {
                beanContext.getBean(definition);
            } catch (Exception e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Could not resolve the OpenID provider metadata [{}] at startup. It will be retried on first use, no more often than every {} seconds.",
                        definition.getDeclaredQualifier(), DefaultOpenIdProviderMetadataFetcher.RETRY_BACKOFF.toSeconds(), e);
                }
            }
        }
    }
}
