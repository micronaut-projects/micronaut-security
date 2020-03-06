package io.micronaut.security.utils.serverrequestcontextspec;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.reactivex.Flowable;
import io.reactivex.Single;
import io.reactivex.schedulers.Schedulers;
import reactor.core.publisher.Flux;

@Requires(property = "spec.name", value = "ServerRequestContextReactiveSpec")
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller("/test/request-context")
class MyController {

    @Get
    Flowable<Message> index() {
        return Flowable.just("foo")
                .flatMapSingle(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Single.just(new Message("Sergio"));
                    }
                    return Single.just(new Message("Anonymous"));
                });
    }

    @Get("/simple")
    Flowable<Message> simple() {
        if (ServerRequestContext.currentRequest().isPresent()) {
            return Flowable.just(new Message("Sergio"));
        }
        return Flowable.just(new Message("Anonymous"));
    }

    @Get("/flowable-subscribeon")
    Flowable<Message> flowableSubscribeOn() {
        return Flowable.just("foo")
                .flatMapSingle(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Single.just(new Message("Sergio"));
                    }
                    return Single.just(new Message("Anonymous"));
                }).subscribeOn(Schedulers.io());
    }


    @Get("/flowable-callable")
    Flowable<Message> flowableCallable() {
        return Flowable.fromCallable(() -> "foo")
                .subscribeOn(Schedulers.io())
                .flatMapSingle(name -> {
                    if (ServerRequestContext.currentRequest().isPresent()) {
                        return Single.just(new Message("Sergio"));
                    }
                    return Single.just(new Message("Anonymous"));
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
