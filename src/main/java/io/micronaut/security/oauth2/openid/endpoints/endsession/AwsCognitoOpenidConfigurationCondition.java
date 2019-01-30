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

/**
 * Condition which evaluates to true if micronaut.security.oauth.openid-configuration contains cognito.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class AwsCognitoOpenidConfigurationCondition extends OpenidConfigurationCondition {
    @Override
    protected String getSearchSequence() {
        return "cognito";
    }
}
