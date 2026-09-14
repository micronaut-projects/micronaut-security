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
package io.micronaut.security.token.propagation;

import io.micronaut.context.exceptions.ConfigurationException;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.util.OutgoingRequestProcessorMatcher;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Base implementation class for {@link OutgoingRequestProcessorMatcher}.
 *
 * @author Álvaro Sánchez-Mariscal
 * @since 3.4.2
 */
public abstract class AbstractOutgoingRequestProcessorMatcher implements OutgoingRequestProcessorMatcher {

    private static final String SERVICE_ID_REGEX = "service-id-regex";
    private static final String URI_REGEX = "uri-regex";

    protected volatile String serviceIdRegex;

    protected volatile String uriRegex;

    protected volatile Pattern serviceIdPattern;

    protected volatile Pattern uriPattern;

    /**
     * @return a regular expression to match the service.
     */
    @Nullable
    public String getServiceIdRegex() {
        return this.serviceIdRegex;
    }

    /**
     * a regular expression to match the service id.
     * @param serviceIdRegex serviceId regular expression
     * @throws ConfigurationException if the value is not a valid regular expression
     */
    public void setServiceIdRegex(@Nullable String serviceIdRegex) {
        this.serviceIdPattern = compile(SERVICE_ID_REGEX, serviceIdRegex);
        this.serviceIdRegex = serviceIdRegex;
    }

    /**
     *
     * @return a regular expression to match the uri.
     */
    @Nullable
    public String getUriRegex() {
        return this.uriRegex;
    }

    /**
     * a regular expression to match the uri.
     * @param uriRegex uri regular expression
     * @throws ConfigurationException if the value is not a valid regular expression
     */
    public void setUriRegex(@Nullable String uriRegex) {
        this.uriPattern = compile(URI_REGEX, uriRegex);
        this.uriRegex = uriRegex;
    }

    @Override
    @Nullable
    public Pattern getServiceIdPattern() {
        return serviceIdPattern;
    }

    @Override
    @Nullable
    public Pattern getUriPattern() {
        return uriPattern;
    }

    @Nullable
    private static Pattern compile(String propertyName, @Nullable String regex) {
        if (regex == null) {
            return null;
        }
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new ConfigurationException("Invalid regular expression '" + regex + "' for property " + propertyName + ": " + e.getDescription(), e);
        }
    }

}
