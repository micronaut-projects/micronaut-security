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

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.util.OutgointRequestProcessorMatcher;

import java.util.regex.Pattern;

/**
 * Base implementation class for {@link OutgointRequestProcessorMatcher}.
 *
 * @author Álvaro Sánchez-Mariscal
 * @since 3.4.2
 */
public abstract class AbstractOutgoingRequestProcessorMatcher implements OutgointRequestProcessorMatcher {

    protected String serviceIdRegex;

    protected String uriRegex;

    protected Pattern serviceIdPattern;

    protected Pattern uriPattern;

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
     */
    public void setServiceIdRegex(@Nullable String serviceIdRegex) {
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
     */
    public void setUriRegex(@Nullable String uriRegex) {
        this.uriRegex = uriRegex;
    }

    @Override
    @Nullable
    public Pattern getServiceIdPattern() {
        if (this.serviceIdPattern == null && this.serviceIdRegex != null) {
            serviceIdPattern = Pattern.compile(this.serviceIdRegex);
        }
        return serviceIdPattern;
    }

    @Override
    @Nullable
    public Pattern getUriPattern() {
        if (this.uriPattern == null && this.uriRegex != null) {
            uriPattern = Pattern.compile(this.uriRegex);
        }
        return uriPattern;
    }

}
