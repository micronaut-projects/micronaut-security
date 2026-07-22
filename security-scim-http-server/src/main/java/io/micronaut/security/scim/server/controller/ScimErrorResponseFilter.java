/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.scim.server.controller;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.protocol.ScimError;
import io.micronaut.security.scim.server.protocol.ScimMediaType;

@Internal
@Requires(property = ScimServerConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@ServerFilter("${" + ScimServerConfiguration.PREFIX + ".path:" + ScimServerConfiguration.DEFAULT_PATH + "}/**")
final class ScimErrorResponseFilter implements Ordered {
    @ResponseFilter
    void formatError(MutableHttpResponse<Object> response) {
        int status = response.code();
        if (status < 400 || response.getBody().orElse(null) instanceof ScimError) {
            return;
        }
        response.contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .body(ScimError.of(status, null, response.reason()));
    }

    @Override
    public int getOrder() {
        return HIGHEST_PRECEDENCE;
    }
}
