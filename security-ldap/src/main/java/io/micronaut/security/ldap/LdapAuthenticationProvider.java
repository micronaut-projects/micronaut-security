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
package io.micronaut.security.ldap;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.util.StringUtils;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import jakarta.inject.Named;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import java.io.Closeable;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

import static io.micronaut.security.utils.LoggingUtils.debug;
import static io.micronaut.security.utils.LoggingUtils.sanitize;
import static io.micronaut.security.utils.LoggingUtils.sanitizeAll;

/**
 * Authenticates against an LDAP server using the configuration provided through
 * {@link LdapConfiguration}. One provider will be created for each configuration.
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 * @author James Kleeh
 * @since 1.0
 */
public class LdapAuthenticationProvider<T, I, S> implements ExecutorAuthenticationProvider<T, I, S>, Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticationProvider.class);

    private final LdapConfiguration configuration;
    private final LdapSearchService ldapSearchService;
    private final ContextBuilder contextBuilder;
    private final ContextAuthenticationMapper contextAuthenticationMapper;
    private final LdapGroupProcessor ldapGroupProcessor;
    private final Scheduler scheduler;

    /**
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @param executorService             Executor Service
     */
    public LdapAuthenticationProvider(LdapConfiguration configuration,
                                      LdapSearchService ldapSearchService,
                                      ContextBuilder contextBuilder,
                                      ContextAuthenticationMapper contextAuthenticationMapper,
                                      LdapGroupProcessor ldapGroupProcessor,
                                      @Named(TaskExecutors.IO) ExecutorService executorService) {
        this.configuration = configuration;
        this.ldapSearchService = ldapSearchService;
        this.contextBuilder = contextBuilder;
        this.contextAuthenticationMapper = contextAuthenticationMapper;
        this.ldapGroupProcessor = ldapGroupProcessor;
        this.scheduler = Schedulers.fromExecutorService(executorService);
    }

    @Override
    public AuthenticationResponse authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        String username = authenticationRequest.getIdentity().toString();
        // the username comes from the client before it is authenticated: never log it as it was received
        String loggableUsername = sanitize(username);
        S secret = authenticationRequest.getSecret();
        if (secret == null) {
            debug(LOG, "Rejecting authentication for user [{}] because the supplied secret is null", loggableUsername);
            return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }
        String password = secret.toString();
        if (StringUtils.isEmpty(password)) {
            // RFC 4513 section 5.1.2: a simple bind with a non-empty DN and an empty password is an
            // unauthenticated bind, which some directories (e.g. Active Directory) accept by default.
            // Never send it to the server.
            debug(LOG, "Rejecting authentication for user [{}] because the supplied secret is empty", loggableUsername);
            return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Starting authentication with configuration [{}]", configuration.getName());
            LOG.debug("Attempting to initialize manager context");
        }
        DirContext managerContext;
        try {
            managerContext = contextBuilder.build(configuration.getManagerSettings());
            debug(LOG, "Manager context initialized successfully");
        } catch (NamingException e) {
            return unknownFailure("manager bind", loggableUsername, e);
        }

        debug(LOG, "Attempting to authenticate with user [{}]", loggableUsername);

        try {
            Optional<LdapSearchResult> optionalResult;
            try {
                optionalResult = ldapSearchService.searchFirst(managerContext, configuration.getSearch().getSettings(new Object[]{username}));
            } catch (NamingException e) {
                return unknownFailure("user search", loggableUsername, e);
            }
            if (optionalResult.isEmpty()) {
                debug(LOG, "User not found [{}]", loggableUsername);
                return rejectUnknownUser(requestContext, authenticationRequest);
            }

            LdapSearchResult result = optionalResult.get();
            debug(LOG, "User found in context [{}]. Attempting to bind.", sanitize(result.getDn()));

            AuthenticationResponse bindFailure = bindUserAndLoadAttributes(result, loggableUsername, password);
            if (bindFailure != null) {
                return bindFailure;
            }

            debug(LOG, "Successfully bound user [{}]. Attempting to retrieve groups.", sanitize(result.getDn()));

            Set<String> groups;
            try {
                groups = searchGroups(managerContext, result, loggableUsername);
            } catch (NamingException e) {
                return failureOfAFoundUser("group search", loggableUsername, e, true);
            }

            // guarded explicitly: sanitizeAll copies the set even when TRACE is off
            if (LOG.isTraceEnabled()) {
                LOG.trace("Attempting to map [{}] with groups [{}] to an authentication response.", loggableUsername, sanitizeAll(groups));
            }

            AuthenticationResponse response = contextAuthenticationMapper.map(result.getAttributes(), username, groups);
            if (response.isAuthenticated()) {
                debug(LOG, "Response successfully created for [{}]. Response is authenticated: [{}]", loggableUsername, response.isAuthenticated());
            }
            return response;
        } finally {
            contextBuilder.close(managerContext);
        }
    }

    /**
     * Binds as the user found by the search and, if the result carries no attributes, fetches them with that bind.
     *
     * @param result           The entry found for the username
     * @param loggableUsername The username, sanitized for logging
     * @param password         The password to bind with
     * @return {@code null} if the user is bound and the result carries its attributes, otherwise the failure returned
     * by {@link #failureOfAFoundUser(String, String, NamingException, boolean)}
     */
    private @Nullable AuthenticationResponse bindUserAndLoadAttributes(LdapSearchResult result, String loggableUsername, String password) {
        String dn = result.getDn();
        DirContext userContext = null;
        try {
            try {
                userContext = contextBuilder.build(configuration.getSettings(dn, password));
            } catch (NamingException e) {
                return failureOfAFoundUser("user bind", loggableUsername, e, false);
            }
            if (result.getAttributes() == null) {
                try {
                    // DirContext#getAttributes(String) parses its argument as a JNDI composite name, which
                    // mis-parses DNs containing '/' or '"'. LdapName parses the DN as an LDAP name instead.
                    result.setAttributes(userContext.getAttributes(new LdapName(dn)));
                } catch (NamingException e) {
                    return failureOfAFoundUser("attribute fetch", loggableUsername, e, true);
                }
            }
            return null;
        } finally {
            contextBuilder.close(userContext);
        }
    }

    /**
     * Maps a failure that happens once the search has found the user. The reason must not depend on the user: an
     * unknown username gets the same reasons from {@link #rejectUnknownUser(Object, AuthenticationRequest)}. So the
     * reason only says whether the directory could be reached: {@link AuthenticationFailureReason#UNKNOWN} for an
     * outage, which fails every username alike, and {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH} for any
     * other failure, whatever the directory answered. The log keeps the step and the exception.
     *
     * @param step                The step of the authentication that failed, as it reads in the log
     * @param loggableUsername    The username, sanitized for logging
     * @param e                   The failure
     * @param afterSuccessfulBind Whether the user bind had succeeded: only a client with the correct password reaches
     *                            such a step, and its failure usually means a misconfiguration, so it is logged at WARN
     * @return an {@link AuthenticationFailureReason#UNKNOWN} failure for an outage, otherwise a
     * {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH} failure
     */
    private static AuthenticationResponse failureOfAFoundUser(String step, String loggableUsername, NamingException e, boolean afterSuccessfulBind) {
        AuthenticationFailureReason reason = isOutage(e) ? AuthenticationFailureReason.UNKNOWN : AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH;
        // guarded explicitly: loggable builds the exception text even when the level is off
        if (afterSuccessfulBind) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("LDAP {} failed for user [{}] after a successful bind; returning {}. Encountered {}", step, loggableUsername, reason, loggable(e));
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("LDAP {} failed for user [{}]; returning {}. Encountered {}", step, loggableUsername, reason, loggable(e));
        }
        return AuthenticationResponse.failure(reason);
    }

    /**
     * @param e A failure
     * @return Whether the failure means that the directory could not be reached or could not serve the request, which
     * fails every username alike: a {@link CommunicationException} or a {@link ServiceUnavailableException}, such as
     * result codes 51 ({@code busy}) and 52 ({@code unavailable})
     */
    private static boolean isOutage(NamingException e) {
        return e instanceof CommunicationException || e instanceof ServiceUnavailableException;
    }

    /**
     * Logs a failure that happens before the user is known and returns {@link AuthenticationFailureReason#UNKNOWN}.
     *
     * @param step             The step of the authentication that failed, as it reads in the log
     * @param loggableUsername The username, sanitized for logging
     * @param e                The failure
     * @return an {@link AuthenticationFailureReason#UNKNOWN} failure
     */
    private static AuthenticationResponse unknownFailure(String step, String loggableUsername, NamingException e) {
        // guarded explicitly: loggable builds the exception text even when DEBUG is off
        if (LOG.isDebugEnabled()) {
            LOG.debug("LDAP {} failed for user [{}]; returning UNKNOWN. Encountered {}", step, loggableUsername, loggable(e));
        }
        return AuthenticationResponse.failure(AuthenticationFailureReason.UNKNOWN);
    }

    private Set<String> searchGroups(DirContext managerContext, LdapSearchResult result, String loggableUsername) throws NamingException {
        LdapConfiguration.GroupConfiguration groupSettings = configuration.getGroups();
        if (!groupSettings.isEnabled()) {
            debug(LOG, "Group search is disabled for configuration [{}]", configuration.getName());
            return Collections.emptySet();
        }
        Set<String> groups = ldapGroupProcessor.process(groupSettings.getAttribute(), result, () -> {
            Object[] params = new Object[]{
                    groupSettings.getFilterAttribute()
                            .map(attr -> result.getAttributes().getValue(attr))
                            .orElse(result.getDn())
            };
            return ldapSearchService.search(managerContext, groupSettings.getSearchSettings(params));
        });
        // guarded explicitly: sanitizeAll copies the set even when DEBUG is off
        if (LOG.isDebugEnabled()) {
            LOG.debug("Group search returned [{}] for user [{}]", sanitizeAll(groups), loggableUsername);
        }
        return groups;
    }

    /**
     * Rejects an authentication request whose username did not match any directory entry.
     * <p>
     * To prevent username enumeration (CWE-204) the response is indistinguishable from the one
     * returned for a known username: the failure reason is never
     * {@link AuthenticationFailureReason#USER_NOT_FOUND}, and a bind against a decoy DN is
     * attempted so that an unknown username costs roughly the same client-side directory round
     * trip as a known username with a wrong password. The outcome of that bind only matters when
     * the directory cannot be reached: the reason is then {@link AuthenticationFailureReason#UNKNOWN},
     * as it is for a known username, and {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH}
     * otherwise.
     * The decoy DN is {@link LdapConfiguration.SearchConfiguration#getDecoyDn()} when configured,
     * otherwise a random, non-existent entry under the search base.
     * <p>
     * Only the client-side cost is equalised. A directory may still answer faster for a
     * non-existent DN than for a wrong password; configure a real decoy entry where that matters.
     *
     * @param requestContext        The request context
     * @param authenticationRequest The authentication request, whose identity matched no entry
     * @return an {@link AuthenticationFailureReason#UNKNOWN} failure if the decoy bind fails with a
     * {@link CommunicationException} or a {@link ServiceUnavailableException}, otherwise a
     * {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH} failure
     * @since 5.5.2
     */
    @Experimental
    protected AuthenticationResponse rejectUnknownUser(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        DirContext decoyContext = null;
        try {
            decoyContext = contextBuilder.build(configuration.getSettings(decoyDn(), authenticationRequest.getSecret().toString()));
        } catch (javax.naming.AuthenticationException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Decoy bind for unknown user failed as expected; returning CREDENTIALS_DO_NOT_MATCH. Encountered {}", loggable(e));
            }
        } catch (NamingException e) {
            if (isOutage(e)) {
                // the bind of a known username would have failed alike, and returned UNKNOWN
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Decoy bind for unknown user could not reach the directory; returning UNKNOWN. Encountered {}", loggable(e));
                }
                return AuthenticationResponse.failure(AuthenticationFailureReason.UNKNOWN);
            }
            // Anything other than invalid credentials means the decoy bind was rejected before the
            // password was checked, so the mitigation is not doing its job.
            if (LOG.isWarnEnabled()) {
                LOG.warn("Decoy bind for unknown user failed with {} rather than invalid credentials; check [{}.{}.search.decoy-dn]; returning CREDENTIALS_DO_NOT_MATCH. Encountered {}",
                    e.getClass().getSimpleName(), LdapConfiguration.PREFIX, configuration.getName(), loggable(e));
            }
        } finally {
            contextBuilder.close(decoyContext);
        }
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
    }

    private String decoyDn() {
        LdapConfiguration.SearchConfiguration search = configuration.getSearch();
        String configured = search.getDecoyDn();
        if (StringUtils.isNotEmpty(configured)) {
            return configured;
        }
        // random so that the bind is not a fixed fingerprint in directory audit logs
        String rdn = "cn=" + UUID.randomUUID();
        String base = search.getBase();
        return StringUtils.isEmpty(base) ? rdn : rdn + "," + base;
    }

    /**
     * {@link NamingException#getMessage()} carries only the explanation; {@link NamingException#toString()} adds the
     * exception type and the root cause, such as a refused connection or a failed TLS handshake.
     *
     * @param e The exception
     * @return The exception type, explanation and root cause, sanitized for logging
     */
    private static String loggable(NamingException e) {
        return sanitize(e.toString());
    }

    @Override
    public void close() {
        //No op
    }
}
