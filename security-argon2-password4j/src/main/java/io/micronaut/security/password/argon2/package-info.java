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
/**
 * Argon2id implementation of {@link io.micronaut.security.password.PasswordEncoder}.
 *
 * <p>Encoded passwords use the PHC string format, for example
 * {@code $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>}.</p>
 *
 * @see <a href="https://github.com/C2SP/C2SP/blob/main/phc-strings.md">PHC string format</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9106">RFC 9106: Argon2</a>
 * @since 5.5.0
 */
@Configuration
@NullMarked
package io.micronaut.security.password.argon2;

import io.micronaut.context.annotation.Configuration;
import org.jspecify.annotations.NullMarked;
