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

import io.micronaut.core.util.Toggleable;

import javax.annotation.Nonnull;

/**
 * {@link DeniedController} configuration.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface DeniedControllerConfiguration extends Toggleable {
    /**
     *
     * @return The default copy to be used for the HTML page title.
     */
    @Nonnull
    String getTitleCopy();

    /**
     *
     * @return The default copy to be used for the HTML page description paragraph.
     */
    @Nonnull
    String getDescriptionCopy();

    /**
     *
     * @return The default route uri of the {@link DeniedController}.
     */
    @Nonnull
    String getPath();
}
