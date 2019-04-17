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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

/**
 * Informs the user he is trying to access a resource for which he does not have enough privileges.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Secured(SecurityRule.IS_ANONYMOUS)
@Requires(property = DeniedControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Controller("${" + DeniedControllerConfigurationProperties.PREFIX + ".path:/denied}")
public class DeniedController {

    private static final String DENIED_HTML = "<!DOCTYPE html>" +
            "<html>\n" +
            "<head>\n" +
            "    <title>@title@</title>\n" +
            "</head>\n" +
            "<body>\n" +
            "<h1>@title@</h1>\n" +
            "<p>@description@</p>\n" +
            "</body>\n" +
            "</html>";

    private final String html;

    /**
     * Constructs a HTML output by replacing some placeholders with values coming from the configuration.
     *
     * @param deniedControllerConfiguration {@link DeniedController} configuration.
     */
    public DeniedController(DeniedControllerConfiguration deniedControllerConfiguration) {
        this.html = DENIED_HTML.replaceAll("@title@", deniedControllerConfiguration.getTitleCopy())
                .replaceAll("@description@", deniedControllerConfiguration.getDescriptionCopy());
    }

    /**
     *
     * @return a HTML 5 simple page.
     */
    @Produces(MediaType.TEXT_HTML)
    @Get
    public String index() {
        return html;
    }

}
