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
package io.micronaut.security.endpoints;

/**
 * Base implementation class for all controller configuration classes.
 *
 * @author Álvaro Sánchez-Mariscal
 */
public abstract class AbstractControllerConfigurationProperties implements ControllerConfiguration {

    protected boolean enabled;
    protected String path;

    /**
     * @return true if you want to enable the {@link LoginController}
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getPath() {
        return this.path;
    }

}
