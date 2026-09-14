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
package io.micronaut.security.fetchmetadata.rules;

import io.micronaut.core.annotation.Internal;

/**
 * Orders the built-in rules according to the recommended resource isolation policy.
 * Gaps between values allow custom rules to be inserted at a specific policy stage.
 */
@Internal
final class FetchMetadataRuleOrder {

    static final int NO_FETCH_METADATA = 100;
    static final int SAME_ORIGIN = 200;
    static final int SAME_SITE = 300;
    static final int BROWSER_INITIATED = 400;
    static final int SIMPLE_NAVIGATION = 500;
    static final int CROSS_ORIGIN = 600;

    private FetchMetadataRuleOrder() {
    }
}
