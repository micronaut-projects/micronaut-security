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
package io.micronaut.security.oauth2.proxy;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.netty.NettyHttpResponseBuilder;
import io.netty.buffer.ByteBuf;
import io.netty.util.ReferenceCountUtil;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import reactor.core.publisher.Flux;

/**
 * {@link HttpBodyReleaser} for the Netty based HTTP runtime.
 * <p>
 * A Netty response keeps its body as reference-counted buffers or, for a streamed response, as a publisher of
 * them. Neither is reclaimed by garbage collection, so a response which is discarded without being read has to
 * release them explicitly. A full response is released in place. A streamed response is subscribed to so that
 * every chunk is released as it arrives; errors while draining it are ignored because the response is being
 * dropped anyway.
 * <p>
 * The bean is only available when a {@link NettyHttpResponseBuilder} is present. Responses which are not
 * Netty responses are left untouched.
 */
@Requires(classes = NettyHttpResponseBuilder.class)
@Singleton
@Internal
final class NettyHttpBodyReleaser implements HttpBodyReleaser {

    /**
     * Releases the Netty buffers backing the body of the response, if it is a mutable Netty response.
     *
     * @param response The response whose body is discarded
     */
    @Override
    public void release(HttpResponse<?> response) {
        if (response instanceof MutableHttpResponse<?> mutableHttpResponse) {
            NettyBodyDiscarder.discard(mutableHttpResponse);
        }
    }

    /**
     * Isolates the Netty specific code so that {@link WellKnownProxyFilter} can be loaded when Netty is absent.
     */
    private static final class NettyBodyDiscarder {
        private NettyBodyDiscarder() {
        }

        /**
         * Releases the full body of a response, or drains and releases every chunk of a streamed one.
         *
         * @param response The response whose body is discarded
         */
        static void discard(@NonNull MutableHttpResponse<?> response) {
            if (response instanceof NettyHttpResponseBuilder builder) {
                try {
                    if (builder.isStream()) {
                        Flux.from(builder.toStreamHttpResponse()).subscribe(ReferenceCountUtil::release, t -> { });
                    } else if (response.getBody().orElse(null) instanceof ByteBuf) {
                        // toFullHttpResponse() throws for any body which is not a ByteBuf
                        ReferenceCountUtil.release(builder.toFullHttpResponse());
                    }
                } catch (RuntimeException ignored) {
                    // the response is being dropped anyway; releasing must never fail the request
                }
            }
        }
    }
}
