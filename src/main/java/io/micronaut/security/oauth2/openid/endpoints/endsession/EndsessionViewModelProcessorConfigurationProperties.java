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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.views.model.ViewModelProcessor;

/**
 * {@link ConfigurationProperties} implementation of {@link EndsessionViewModelProcessorConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(classes = ViewModelProcessor.class)
@ConfigurationProperties(EndsessionViewModelProcessorConfigurationProperties.PREFIX)
public class EndsessionViewModelProcessorConfigurationProperties implements EndsessionViewModelProcessorConfiguration {
    public static final String PREFIX = EndSessionEndpointConfigurationProperties.PREFIX + ".view-model-processor";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default key name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_ENDSESSIONURLKEY = "endsessionurl";

    private boolean enabled = DEFAULT_ENABLED;

    private String endSessionUrlKey = DEFAULT_ENDSESSIONURLKEY;

    /**
     * @return true if you want to enable the {@link EndsessionViewModelProcessor}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether the {@link EndsessionViewModelProcessor} is enabled. Default value ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled True if is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Model key name. Default value ({@value #DEFAULT_ENDSESSIONURLKEY}).
     * @param endSessionUrlKey the key name which will be used in the model map.
     */
    public void setEndSessionUrlKey(String endSessionUrlKey) {
        this.endSessionUrlKey = endSessionUrlKey;
    }

    /**
     *
     * @return the key name which will be used in the model map.
     */
    @Override
    public String getEndSessionUrlKey() {
        return this.endSessionUrlKey;
    }
}
