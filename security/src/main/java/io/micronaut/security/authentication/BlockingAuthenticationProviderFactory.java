package io.micronaut.security.authentication;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.scheduling.TaskExecutors;
import jakarta.inject.Named;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;

@Factory
class BlockingAuthenticationProviderFactory {

    private final Scheduler scheduler;

    BlockingAuthenticationProviderFactory(@Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        this.scheduler = Schedulers.fromExecutorService(executorService);
    }

    @EachBean(BlockingAuthenticationProvider.class)
    <T> AuthenticationProvider<T> createAuthenticationProvider(BlockingAuthenticationProvider<T> blockingAuthenticationProvider) {
        return new BlockingAuthenticationProviderAdapter<>(blockingAuthenticationProvider, scheduler);
    }
}
