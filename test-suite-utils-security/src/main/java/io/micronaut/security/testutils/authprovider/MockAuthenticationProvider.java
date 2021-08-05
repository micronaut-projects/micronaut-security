/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.testutils.authprovider;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxSink;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Utility class to mock authentication scenarios.
 */
public class MockAuthenticationProvider implements AuthenticationProvider  {

    private final List<SuccessAuthenticationScenario> successAuthenticationScenarioList;
    private final List<FailedAuthenticationScenario> failedAuthenticationScenarios;

    /**
     * @param successAuthenticationScenarioList Successful scenarios
     */
    public MockAuthenticationProvider(List<SuccessAuthenticationScenario> successAuthenticationScenarioList) {
        this.successAuthenticationScenarioList = successAuthenticationScenarioList;
        this.failedAuthenticationScenarios = Collections.emptyList();
    }

    /**
     * @param successAuthenticationScenarioList Successful scenarios
     * @param failedAuthenticationScenarioList Failure scenarios
     */
    public MockAuthenticationProvider(List<SuccessAuthenticationScenario> successAuthenticationScenarioList,
                                      List<FailedAuthenticationScenario> failedAuthenticationScenarioList) {
        this.successAuthenticationScenarioList = successAuthenticationScenarioList;
        this.failedAuthenticationScenarios = failedAuthenticationScenarioList;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Flux.create(emitter -> {
            Optional<SuccessAuthenticationScenario> successAuth = successAuthenticationScenarioList.stream()
                    .filter(scenario -> {
                        if (scenario.getPassword() != null) {
                            return scenario.getPassword().equalsIgnoreCase(authenticationRequest.getSecret().toString()) &&
                                    scenario.getUsername().equalsIgnoreCase(authenticationRequest.getIdentity().toString());
                        }
                        return scenario.getUsername().equalsIgnoreCase(authenticationRequest.getIdentity().toString());
                    })
                    .findFirst();
            if (successAuth.isPresent()) {
                SuccessAuthenticationScenario scenario = successAuth.get();
                emitter.next(AuthenticationResponse.success(scenario.getUsername(), scenario.getRoles(), scenario.getAttributes()));
                emitter.complete();
            } else {
                Optional<FailedAuthenticationScenario> failedAuthenticationScenario = failedAuthenticationScenarios.stream()
                        .filter(scenario -> scenario.getUsername().equalsIgnoreCase(authenticationRequest.getIdentity().toString()))
                        .findFirst();
                if (failedAuthenticationScenario.isPresent()) {
                    emitter.error(AuthenticationResponse.exception(failedAuthenticationScenario.get().getReason()));
                } else {
                    emitter.error(AuthenticationResponse.exception());
                }
            }
            }, FluxSink.OverflowStrategy.ERROR);
    }
}
