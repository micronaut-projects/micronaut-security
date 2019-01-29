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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import java.util.Optional;

public abstract class OpenidConfigurationCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context) {
        BeanContext beanContext = context.getBeanContext();
        if (beanContext instanceof PropertyResolver) {
            PropertyResolver propertyResolver = (PropertyResolver) beanContext;
            Optional<String> openIdConfigurationUrl = propertyResolver.get(OauthConfigurationProperties.PREFIX + ".openid-configuration", String.class);
            return openIdConfigurationUrl.map(s -> s.contains(getSearchSequence())).orElse(false);
        }
        return false;
    }

    abstract protected String getSearchSequence();
}
