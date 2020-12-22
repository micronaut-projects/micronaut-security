/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.client.clientcredentials;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import org.reactivestreams.Processor;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Utility class to cache of a publisher result.
 * @author Sergio del Amo
 * @since 2.2.0
 * @param <T> The element to be returned by the publisher
 */
@Experimental
@Internal
class CacheableProcessor<T> implements Processor<T, T> {

    @Nullable
    private T element;

    @Nullable
    private Throwable throwable;

    private boolean complete;

    @Nullable
    private Subscription subscription;

    @NonNull
    private Queue<ElementSubscription<T>> subscriptions = new ConcurrentLinkedQueue<>();

    @Nullable
    private final Function<T, T> transformer;

    /**
     * Constructor.
     */
    CacheableProcessor() {
        this.transformer = null;
    }

    /**
     *
     * @param transformer A transformation function to be applied when an element is received.
     */
    CacheableProcessor(@NonNull Function<T, T> transformer) {
        this.transformer = transformer;
    }

    /**
     * Invalidates the cache.
     */
    public void clear() {
        this.complete = false;
        this.element = null;
        this.throwable = null;
        if (subscription != null) {
            subscription.cancel();
            subscription = null;
        }
        subscriptions = subscriptions.stream()
                .filter(elementSubscription -> !elementSubscription.isCanceled() && !elementSubscription.isComplete())
                .collect(Collectors.toCollection(ConcurrentLinkedQueue::new));
    }

    // Subscriber

    @Override
    public void onSubscribe(Subscription s) {
        this.subscription = s;
    }

    @Override
    public void onNext(T el) {
        this.element = transformer != null ? transformer.apply(el) : el;
        flowData();
    }

    @Override
    public void onError(Throwable t) {
        this.throwable = t;
        flowData();
    }

    @Override
    public void onComplete() {
        this.complete = true;
    }

    @Override
    public void subscribe(Subscriber<? super T> s) {
        ElementSubscription<T> subscription = new ElementSubscription<>(s, this);
        this.subscriptions.add(subscription);
        s.onSubscribe(subscription);
    }

    public void onElementsRequested() {
        if (element == null && subscription != null) {
            subscription.request(1);
        } else {
            flowData();
        }
    }

    private void flowData() {
        for (ElementSubscription<T> s : subscriptions) {
            if (s.isCanceled() || s.isComplete()) {
                continue;
            }
            if (element != null) {
                if (s.isElementsRequested()) {
                    s.getSubscriber().onNext(element);
                    s.setElementsRequested(false);
                    if (complete) {
                        s.getSubscriber().onComplete();
                        s.setComplete(true);
                    }
                }
            } else if (throwable != null) {
                s.getSubscriber().onError(throwable);
            }
        }
    }

    /**
     *
     * @return The subscription to the
     */
    @Nullable
    public Subscription getSubscription() {
        return subscription;
    }

    /**
     *
     * @return The element
     */
    @Nullable
    public T getElement() {
        return this.element;
    }

    /**
     *
     * @param <T> The element type
     */
    private static class ElementSubscription<T> implements Subscription {
        private final Subscriber<? super T> subscriber;
        private final CacheableProcessor<T> listener;
        private boolean canceled;
        private boolean elementsRequested;
        private boolean complete;

        /**
         *
         * @param subscriber The subscriber
         * @param listener The Listener
         */
        public ElementSubscription(Subscriber<? super T> subscriber,
                                   CacheableProcessor<T> listener) {
            this.subscriber = subscriber;
            this.listener = listener;
        }

        /**
         *
         * @param elementsRequested true if new elements where requested
         */
        public void setElementsRequested(boolean elementsRequested) {
            this.elementsRequested = elementsRequested;
        }

        /**
         *
         * @return True if elements were requested
         */
        public boolean isElementsRequested() {
            return elementsRequested;
        }

        /**
         *
         * @return Whether the subscription is canceled
         */
        public boolean isCanceled() {
            return canceled;
        }

        /**
         *
         * @return Whether the subscription is complete
         */
        public boolean isComplete() {
            return complete;
        }

        /**
         *
         * @param complete flags the subscription as complete
         */
        public void setComplete(boolean complete) {
            this.complete = complete;
        }

        /**
         *
         * @return The subscriber
         */
        public Subscriber<? super T> getSubscriber() {
            return subscriber;
        }

        @Override
        public void cancel() {
            this.canceled = true;
        }

        @Override
        public void request(long n) {
            if (n > 0) {
                this.elementsRequested = true;
                listener.onElementsRequested();
            }
        }
    }

}



