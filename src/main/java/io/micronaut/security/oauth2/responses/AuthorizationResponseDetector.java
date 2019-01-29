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

package io.micronaut.security.oauth2.responses;

import io.micronaut.http.HttpParameters;

import java.util.Map;

/**
 * Utility to verify if a particular object encapsulates an {@link AuthenticationResponse}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public class AuthorizationResponseDetector {

    /**
     *
     * @param object Object being evaluated as a Authorization response
     * @return true if the object encapsulates an {@link AuthenticationResponse}.
     */
    public static boolean isAuthorizationResponse(Object object) {
        if (object instanceof HttpParameters) {
            return isHttpParametersAnAuthorizationResponse((HttpParameters) object);
        } else if (object instanceof Map) {
            return isMapAnAuthorizationResponse((Map) object);
        }
        return false;
    }

    /**
     *
     * @param parameters Http parameters
     * @return true if the parameters contains a param named code
     */
    public static boolean isHttpParametersAnAuthorizationResponse(HttpParameters parameters) {
        return parameters.get(AuthenticationResponse.KEY_CODE, String.class).isPresent();
    }

    /**
     *
     * @param formFields A Map encapsulating the form url encoded payload.
     * @return true if the response is consider an error.
     */
    public static boolean isMapAnAuthorizationResponse(Map formFields) {
        Object value = formFields.get(AuthenticationResponse.KEY_CODE);
        if (value instanceof String) {
            return true;
        }
        return false;
    }
}
