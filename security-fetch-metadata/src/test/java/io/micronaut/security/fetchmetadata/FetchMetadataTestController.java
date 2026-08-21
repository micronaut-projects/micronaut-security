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
package io.micronaut.security.fetchmetadata;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.server.cors.CrossOrigin;

@Controller("/fetch-metadata")
final class FetchMetadataTestController {

    @Get(produces = MediaType.TEXT_PLAIN)
    String get() {
        return "ok";
    }

    @Post(produces = MediaType.TEXT_PLAIN)
    String post() {
        return "ok";
    }

    @Get(uri = "/filtered/test", produces = MediaType.TEXT_PLAIN)
    String filtered() {
        return "ok";
    }

    // tag::cors[]
    @CrossOrigin("https://allowed.example")
    @Get(uri = "/cors", produces = MediaType.TEXT_PLAIN)
    String cors() {
        return "ok";
    }
    // end::cors[]
}
