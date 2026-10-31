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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.core.annotation.NonNull;

/**
 * Matches when the OAuth 2.0 client named by the bean qualifier is enabled.
 *
 * <p>Used instead of throwing {@link io.micronaut.context.exceptions.DisabledBeanException} from an
 * {@code @EachBean} factory method: a condition removes the disabled candidate before eager
 * initialization, whereas an exception thrown while a {@code @Context} definition is being
 * initialized stops the remaining candidates of that definition from being created at startup.</p>
 *
 * @author Sergio del Amo
 * @since 3.11.3
 */
@Internal
public class OauthClientEnabledCondition extends AbstractCondition {

    @Override
    @NonNull
    protected String getFailureMessagePrefix(@NonNull String name) {
        return "Skipped bean creation for OAuth 2.0 client [" + name;
    }

    @Override
    protected boolean handleConfigurationEnabled(@NonNull OauthClientConfiguration clientConfiguration,
                                                 @NonNull ConditionContext<?> context,
                                                 @NonNull String failureMsgPrefix) {
        return true;
    }
}
