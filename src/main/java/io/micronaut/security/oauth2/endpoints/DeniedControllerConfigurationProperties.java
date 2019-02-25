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

package io.micronaut.security.oauth2.endpoints;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.config.SecurityConfigurationProperties;

import javax.annotation.Nonnull;

/**
 * {@link ConfigurationProperties} implementation of {@link DeniedControllerConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(DeniedControllerConfigurationProperties.PREFIX)
public class DeniedControllerConfigurationProperties implements DeniedControllerConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".endpoints.denied";

    public static final String DEFAULT_TITLE = "Denied";
    public static final String DEFAULT_DESCRIPTION = "Sorry, you're not authorized to view this page";
    public static final String DEFAULT_PATH = "/denied";

    @Nonnull
    private String titleCopy = DEFAULT_TITLE;

    @Nonnull
    private String descriptionCopy = DEFAULT_DESCRIPTION;

    @Nonnull
    private String path = DEFAULT_PATH;

    /**
     * The default route uri of the {@link DeniedController}. Default value ({@value #DEFAULT_PATH}).
     * @param path @return The default route uri of the {@link DeniedController}.
     */
    public void setPath(@Nonnull String path) {
        this.path = path;
    }

    /**
     * The default copy to be used for the HTML page title. Default value ({@value #DEFAULT_TITLE}).
     * @param titleCopy The default copy to be used for the HTML page title.
     */
    public void setTitleCopy(@Nonnull String titleCopy) {
        this.titleCopy = titleCopy;
    }

    /**
     * The default copy to be used for the HTML page description paragraph. Default value ({@value DEFAULT_DESCRIPTION}).
     * @param descriptionCopy The default copy to be used for the HTML page description paragraph.
     */
    public void setDescriptionCopy(@Nonnull String descriptionCopy) {
        this.descriptionCopy = descriptionCopy;
    }

    @Override
    @Nonnull
    public String getTitleCopy() {
        return this.titleCopy;
    }

    @Override
    @Nonnull
    public String getDescriptionCopy() {
        return this.descriptionCopy;
    }

    @Override
    @Nonnull
    public String getPath() {
        return this.path;
    }
}
