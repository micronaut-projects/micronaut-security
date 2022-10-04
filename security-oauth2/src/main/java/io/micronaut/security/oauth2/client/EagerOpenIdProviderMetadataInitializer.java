/*
 * Copyright 2017-2022 original authors
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

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * If there is at least one pre-configured OpenId client and
 * "micronaut.security.oauth2.openid.eager-provider-init" is set to true, then this class will
 * initialize all the OpenIdProviderMetadata beans eagerly, which means that the provider's
 * configuration endpoint will be called before the server starts to fetch the necessary metadata.
 * This is especially useful if the mentioned HTTP call causes runtime problems when it blocks the
 * event loop.
 *
 * @author Adam Kobor
 */
@Context
@Requires(beans = OpenIdClientConfiguration.class)
@Requires(
    property = OauthConfigurationProperties.OpenIdConfigurationProperties.PREFIX + ".eager-provider-init",
    value = StringUtils.TRUE
)
public class EagerOpenIdProviderMetadataInitializer {

    private static final Logger LOG = LoggerFactory.getLogger(EagerOpenIdProviderMetadataInitializer.class);

    @Inject
    public EagerOpenIdProviderMetadataInitializer(Collection<OpenIdProviderMetadata> allProviderMetadata) {
        for (OpenIdProviderMetadata providerMetaData : allProviderMetadata) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("OpenIdProviderMetadata was eagerly initialized for the following issuer: {}", providerMetaData.getIssuer());
            }
        }
    }
}
