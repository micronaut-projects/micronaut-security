/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.rules;

import io.micronaut.security.token.RolesFinder;

import javax.inject.Inject;

/**
 * A base {@link ReactiveSecurityRule} class to extend from that provides
 * helper methods to get the roles from the claims and compare them
 * to the roles allowed by the rule.
 *
 * @author Steven Brown
 * @since 2.4
 */
public abstract class AbstractReactiveSecurityRule extends AbstractBaseSecurityRule implements ReactiveSecurityRule {
    /**
     * @param rolesFinder Roles Parser
     */
    @Inject
    public AbstractReactiveSecurityRule(RolesFinder rolesFinder) {
        super(rolesFinder);
    }
}
