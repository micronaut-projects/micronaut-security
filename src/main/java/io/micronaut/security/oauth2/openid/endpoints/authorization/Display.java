/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

/**
 * OpenID connect Display parameter.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID connect / Authentication Request</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public enum Display {

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view. If the display parameter is not specified, this is the default display mode.
     */
    PAGE("page"),

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window. The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
     */
    POPUP("popup"),

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
     */
    TOUCH("touch"),

    /**
     * The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
     */
    WAP("wap");

    private String display;

    /**
     * Instantiates the OpenID connect Display parameter.
     * @param display Display parameter.
     */
    Display(String display) {
        this.display = display;
    }

    /**
     *
     * @return OpenID connect Display parameter
     */
    public String getDisplay() {
        return display;
    }
}
