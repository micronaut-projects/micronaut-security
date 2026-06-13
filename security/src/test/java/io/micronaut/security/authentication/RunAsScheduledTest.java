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
package io.micronaut.security.authentication;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.scheduling.annotation.Scheduled;
import io.micronaut.security.annotation.Attribute;
import io.micronaut.security.annotation.RunAs;
import io.micronaut.security.context.SecurityContextHolder;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RunAsScheduledTest {

    @Test
    void runAsAllowsScheduledJobToDelegateToAServiceThatExpectsAnAuthenticatedUser() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", "RunAsScheduledTest"))) {
            ScheduledRunAsState state = context.getBean(ScheduledRunAsState.class);

            await().atMost(5, SECONDS).untilAsserted(() -> {
                Throwable failure = state.failure.get();
                if (failure != null) {
                    throw new AssertionError("Scheduled job failed", failure);
                }
                Authentication authentication = state.authentication.get();
                assertNotNull(authentication);
                assertEquals("scheduler", authentication.getName());
                assertEquals(List.of("SCHEDULED"), authentication.getRoles().stream().toList());
                assertEquals(
                    Map.of("given_name", "Scheduled"),
                    authentication.getAttributes()
                );
            });
        }
    }

    @Requires(property = "spec.name", value = "RunAsScheduledTest")
    @Singleton
    static final class ScheduledRunAsState {
        final AtomicBoolean executed = new AtomicBoolean();
        final AtomicReference<Authentication> authentication = new AtomicReference<>();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
    }

    @RunAs(
        name = "scheduler",
        roles = {"SCHEDULED"},
        attributes = @Attribute(key = "given_name", value = "Scheduled")
    )
    @Requires(property = "spec.name", value = "RunAsScheduledTest")
    @Singleton
    static class ScheduledRunAsJob {
        private final AuthenticatedUserService authenticatedUserService;
        private final ScheduledRunAsState state;

        ScheduledRunAsJob(AuthenticatedUserService authenticatedUserService, ScheduledRunAsState state) {
            this.authenticatedUserService = authenticatedUserService;
            this.state = state;
        }

        @Scheduled(initialDelay = "10ms", fixedDelay = "10ms")
        void run() {
            if (state.executed.compareAndSet(false, true)) {
                try {
                    state.authentication.set(authenticatedUserService.currentAuthentication());
                } catch (Throwable e) {
                    state.failure.set(e);
                }
            }
        }
    }

    @Requires(property = "spec.name", value = "RunAsScheduledTest")
    @Singleton
    static final class AuthenticatedUserService {

        Authentication currentAuthentication() {
            Authentication authentication = SecurityContextHolder.getSecurityContext().getAuthentication();
            if (authentication == null) {
                throw new IllegalStateException("Expected an authenticated user");
            }
            return authentication;
        }
    }
}
