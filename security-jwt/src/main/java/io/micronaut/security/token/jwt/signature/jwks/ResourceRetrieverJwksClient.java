/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import io.micronaut.context.annotation.Secondary;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.scheduling.TaskExecutors;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutorService;

/**
 * Implementation of {@link JwksClient} that uses the Nimbus library's built-in {@code com.nimbusds.jose.util.ResourceRetriever} interface.
 *
 *  @author Jeremy Grelle
 *  @since 4.5.0
 */
@Singleton
@Secondary
public class ResourceRetrieverJwksClient implements JwksClient {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceRetrieverJwksClient.class);
    private final Scheduler scheduler;
    private final DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 0, 0);

    @Inject
    public ResourceRetrieverJwksClient(@Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        this(Schedulers.fromExecutorService(executorService));
    }

    public ResourceRetrieverJwksClient(Scheduler scheduler) {
        this.scheduler = scheduler;
    }

    @Override
    @SingleResult
    public Publisher<String> load(String providerName, String url) {
        return Mono.fromCallable(() -> {
            try {
                return resourceRetriever.retrieveResource(new URL(url));
            } catch (IOException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Exception loading JWK from " + url, e);
                }
                return null;
            }
        }).map(Resource::getContent)
            .subscribeOn(scheduler);
    }
}
