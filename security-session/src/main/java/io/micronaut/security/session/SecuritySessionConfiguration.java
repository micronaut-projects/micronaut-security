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
package io.micronaut.security.session;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.config.ForbiddenRedirectConfiguration;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RefreshRedirectConfiguration;
import io.micronaut.security.config.UnauthorizedRedirectConfiguration;

/**
 * Defines Session-based Authentication configuration properties.
 * @author Sergio del Amo
 * @since 1.0
 * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration} instead.
 */
@Deprecated
public interface SecuritySessionConfiguration extends Toggleable {

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a successful login.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLoginSuccess()} instead.
     */
    @Deprecated
    String getLoginSuccessTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after logout.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLogout()} instead.
     */
    @Deprecated
    String getLogoutTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a failed login.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLoginFailure()} instead.
     */
    @Deprecated
    String getLoginFailureTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after trying to access a secured route.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getUnauthorized()} instead.
     */
    @Deprecated
    String getUnauthorizedTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after trying to access a secured route for which the does not have sufficient roles.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getForbidden()} instead.
     */
    @Deprecated
    String getForbiddenTargetUrl();

    /**
     * @return True if a redirect should occur when a request is rejected
     * @deprecated Use {@link UnauthorizedRedirectConfiguration#isEnabled()} or {@link ForbiddenRedirectConfiguration#isEnabled()} instead.
     */
    @Deprecated
    boolean isRedirectOnRejection();

    default RedirectConfiguration toRedirectConfiguration() {
        SecuritySessionConfiguration thisConfig = this;
        return new RedirectConfiguration() {
            @NonNull
            @Override
            public String getLoginSuccess() {
                return thisConfig.getLoginSuccessTargetUrl();
            }

            @NonNull
            @Override
            public String getLoginFailure() {
                return thisConfig.getLoginFailureTargetUrl();
            }

            @NonNull
            @Override
            public String getLogout() {
                return thisConfig.getLogoutTargetUrl();
            }

            @NonNull
            @Override
            public UnauthorizedRedirectConfiguration getUnauthorized() {
                return new UnauthorizedRedirectConfiguration() {

                    @Override
                    public boolean isEnabled() {
                        return thisConfig.isRedirectOnRejection();
                    }

                    @NonNull
                    @Override
                    public String getUrl() {
                        return thisConfig.getUnauthorizedTargetUrl();
                    }
                };
            }

            @NonNull
            @Override
            public ForbiddenRedirectConfiguration getForbidden() {
                return new ForbiddenRedirectConfiguration() {
                    @Override
                    public boolean isEnabled() {
                        return thisConfig.isRedirectOnRejection();
                    }

                    @NonNull
                    @Override
                    public String getUrl() {
                        return thisConfig.getForbiddenTargetUrl();
                    }
                };
            }

            @NonNull
            @Override
            public RefreshRedirectConfiguration getRefresh() {
                return new RefreshRedirectConfiguration() {

                    @Override
                    public boolean isEnabled() {
                        return true;
                    }

                    @NonNull
                    @Override
                    public String getUrl() {
                        return "/";
                    }
                };
            }

            @Override
            public boolean isPriorToLogin() {
                return false;
            }
        };
    }
}
