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
import io.micronaut.core.annotation.Order;
import io.micronaut.core.io.buffer.ByteBuffer;
import io.micronaut.core.io.buffer.ByteBufferFactory;
import io.micronaut.core.type.Argument;
import io.micronaut.core.type.Headers;
import io.micronaut.core.type.MutableHeaders;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.body.MessageBodyHandler;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.body.JsonMessageHandler;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.io.InputStream;
import java.io.OutputStream;

@Internal
@Order(JsonMessageHandler.ORDER)
@Singleton
@Requires(beans = JsonMapper.class)
@Consumes(ScimMediaType.APPLICATION_SCIM_JSON)
@Produces(ScimMediaType.APPLICATION_SCIM_JSON)
final class ScimJsonHandler<T> implements MessageBodyHandler<T> {
    private final JsonMessageHandler<T> delegate;

    ScimJsonHandler(JsonMapper jsonMapper) {
        this(new JsonMessageHandler<>(jsonMapper));
    }

    private ScimJsonHandler(JsonMessageHandler<T> delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean isReadable(Argument<T> type, @Nullable MediaType mediaType) {
        return delegate.isReadable(type, mediaType);
    }

    @Override
    @Nullable
    public T read(
        Argument<T> type,
        @Nullable MediaType mediaType,
        Headers httpHeaders,
        ByteBuffer<?> byteBuffer
    ) throws CodecException {
        return delegate.read(type, mediaType, httpHeaders, byteBuffer);
    }

    @Override
    @Nullable
    public T read(
        Argument<T> type,
        @Nullable MediaType mediaType,
        Headers httpHeaders,
        InputStream inputStream
    ) throws CodecException {
        return delegate.read(type, mediaType, httpHeaders, inputStream);
    }

    @Override
    public boolean isWriteable(Argument<T> type, @Nullable MediaType mediaType) {
        return delegate.isWriteable(type, mediaType);
    }

    @Override
    public void writeTo(
        Argument<T> type,
        @Nullable MediaType mediaType,
        T object,
        MutableHeaders outgoingHeaders,
        OutputStream outputStream
    ) throws CodecException {
        delegate.writeTo(type, mediaType, object, outgoingHeaders, outputStream);
    }

    @Override
    public ByteBuffer<?> writeTo(
        Argument<T> type,
        MediaType mediaType,
        T object,
        MutableHeaders outgoingHeaders,
        ByteBufferFactory<?, ?> bufferFactory
    ) throws CodecException {
        return delegate.writeTo(type, mediaType, object, outgoingHeaders, bufferFactory);
    }

    @Override
    public MessageBodyHandler<T> createSpecific(Argument<T> type) {
        return new ScimJsonHandler<>(delegate.createSpecific(type));
    }
}
