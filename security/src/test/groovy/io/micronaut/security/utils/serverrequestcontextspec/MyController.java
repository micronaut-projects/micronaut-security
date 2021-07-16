package io.micronaut.security.utils.serverrequestcontextspec;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Requires(property = "spec.name", value = "ServerRequestContextReactiveSpec")
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller("/test/request-context")
class MyController {

    @Get
    @SingleResult
    Publisher<Message> index() {
        return Mono.just("foo")
                .flatMap(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Mono.just(new Message("Sergio"));
                    }
                    return Mono.just(new Message("Anonymous"));
                });
    }

    @Get("/simple")
    @SingleResult
    Publisher<Message> simple() {
        if (ServerRequestContext.currentRequest().isPresent()) {
            return Flux.just(new Message("Sergio"));
        }
        return Flux.just(new Message("Anonymous"));
    }

    @Get("/flowable-subscribeon")
    @SingleResult
    Publisher<Message> flowableSubscribeOn() {
        return Mono.just("foo")
                .flatMap(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Mono.just(new Message("Sergio"));
                    }
                    return Mono.just(new Message("Anonymous"));
                }).subscribeOn(Schedulers.boundedElastic());
    }


    @Get("/flowable-callable")
    @SingleResult
    Publisher<Message> flowableCallable() {
        return Mono.fromCallable(() -> "foo")
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Mono.just(new Message("Sergio"));
                    }
                    return Mono.just(new Message("Anonymous"));
                });
    }

    @Get("/flux")
    Flux<Message> flux() {
        return Flux.just("foo")
                .flatMap(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Flux.just(new Message("Sergio"));
                    }
                    return Flux.just(new Message("Anonymous"));
                });
    }

    @Get("/flux-subscribeon")
    Flux<Message> fluxSubscribeOn() {
        return Flux.just("foo")
                .flatMap(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Flux.just(new Message("Sergio"));
                    }
                    return Flux.just(new Message("Anonymous"));
                }).subscribeOn(reactor.core.scheduler.Schedulers.elastic());
    }

}
