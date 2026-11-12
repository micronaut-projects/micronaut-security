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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationNotSupportedException;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import java.io.Closeable;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

import static io.micronaut.security.utils.LoggingUtils.debug;

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

    /**
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @since 5.4.0
     */
    public LdapAuthenticationProvider(LdapConfiguration configuration,
                                      LdapSearchService ldapSearchService,
                                      ContextBuilder contextBuilder,
                                      ContextAuthenticationMapper contextAuthenticationMapper,
                                      LdapGroupProcessor ldapGroupProcessor) {
        this.configuration = configuration;
        this.ldapSearchService = ldapSearchService;
        this.contextBuilder = contextBuilder;
        this.contextAuthenticationMapper = contextAuthenticationMapper;
        this.ldapGroupProcessor = ldapGroupProcessor;
    }

    /**
     * @param configuration               The configuration to use to authenticate
     * @param ldapSearchService           The search service
     * @param contextBuilder              The context builder
     * @param contextAuthenticationMapper The authentication mapper
     * @param ldapGroupProcessor          The group processor
     * @param executorService             Ignored. LDAP authentication runs on the executor named by
     *                                    {@link #getExecutorName()} ({@link TaskExecutors#BLOCKING}).
     * @deprecated The executor service is ignored. Use {@link #LdapAuthenticationProvider(LdapConfiguration, LdapSearchService, ContextBuilder, ContextAuthenticationMapper, LdapGroupProcessor)} instead.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    public LdapAuthenticationProvider(LdapConfiguration configuration,
                                      LdapSearchService ldapSearchService,
                                      ContextBuilder contextBuilder,
                                      ContextAuthenticationMapper contextAuthenticationMapper,
                                      LdapGroupProcessor ldapGroupProcessor,
                                      @Named(TaskExecutors.IO) ExecutorService executorService) {
        this(configuration, ldapSearchService, contextBuilder, contextAuthenticationMapper, ldapGroupProcessor);
    }

    @Override
    public AuthenticationResponse authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        String username = authenticationRequest.getIdentity().toString();
        S secret = authenticationRequest.getSecret();
        if (secret == null) {
            debug(LOG, "Rejecting authentication for user [{}] because the supplied secret is null", username);
            return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }
        String password = secret.toString();
        if (StringUtils.isEmpty(password)) {
            // RFC 4513 section 5.1.2: a simple bind with a non-empty DN and an empty password is an
            // unauthenticated bind, which some directories (e.g. Active Directory) accept by default.
            // Never send it to the server.
            debug(LOG, "Rejecting authentication for user [{}] because the supplied secret is empty", username);
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
            debug(LOG, "Failed to create manager context. Returning unknown authentication failure. Encountered {}", e.getMessage());
            return AuthenticationResponse.failure(AuthenticationFailureReason.UNKNOWN);
        }

        debug(LOG, "Attempting to authenticate with user [{}]", username);

        try {
            Optional<LdapSearchResult> optionalResult = ldapSearchService.searchFirst(managerContext, configuration.getSearch().getSettings(new Object[]{username}));

            if (optionalResult.isPresent()) {
                LdapSearchResult result = optionalResult.get();
                debug(LOG, "User found in context [{}]. Attempting to bind.", result.getDn());

                DirContext userContext = null;
                try {
                    String dn = result.getDn();
                    try {
                        userContext = contextBuilder.build(configuration.getSettings(result.getDn(), password));
                    } catch (AuthenticationNotSupportedException | OperationNotSupportedException e) {
                        // The server rejected the user bind itself, so the supplied credentials are not accepted.
                        debug(LOG, "Server rejected bind for user [{}]. {}", username, e);
                        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
                    }
                    if (result.getAttributes() == null) {
                        // DirContext#getAttributes(String) parses its argument as a JNDI composite name, which
                        // mis-parses DNs containing '/' or '"'. LdapName parses the DN as an LDAP name instead.
                        // InvalidNameException is a NamingException and is handled by the enclosing catch.
                        result.setAttributes(userContext.getAttributes(new LdapName(dn)));
                    }
                } finally {
                    contextBuilder.close(userContext);
                }

                debug(LOG, "Successfully bound user [{}]. Attempting to retrieving groups.", result.getDn());

                Set<String> groups = Collections.emptySet();

                LdapConfiguration.GroupConfiguration groupSettings = configuration.getGroups();
                if (groupSettings.isEnabled()) {
                    groups = ldapGroupProcessor.process(groupSettings.getAttribute(), result, () -> {
                        Object[] params = new Object[]{
                                groupSettings.getFilterAttribute()
                                        .map(attr -> result.getAttributes().getValue(attr))
                                        .orElse(result.getDn())
                        };
                        return ldapSearchService.search(managerContext, groupSettings.getSearchSettings(params));
                    });


                    debug(LOG, "Group search returned [{}] for user [{}]", groups, username);
                } else {
                    debug(LOG, "Group search is disabled for configuration [{}]", configuration.getName());
                }

                if (LOG.isTraceEnabled()) {
                    LOG.trace("Attempting to map [{}] with groups [{}] to an authentication response.", username, groups);
                }

                AuthenticationResponse response = contextAuthenticationMapper.map(result.getAttributes(), username, groups);
                if (response.isAuthenticated()) {
                    debug(LOG, "Response successfully created for [{}]. Response is authenticated: [{}]", username, response.isAuthenticated());
                }
                return response;

            } else {
                debug(LOG, "User not found [{}]", username);
                return rejectUnknownUser(requestContext, authenticationRequest);
            }
        } catch (NamingException e) {
            debug(LOG, "Failed to authenticate with user [{}].  {}", username, e);
            if (e instanceof javax.naming.AuthenticationException) {
                return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
            } else {
                return AuthenticationResponse.failure(AuthenticationFailureReason.UNKNOWN);
            }
        } finally {
            contextBuilder.close(managerContext);
        }
    }

    /**
     * Rejects an authentication request whose username did not match any directory entry.
     * <p>
     * To prevent username enumeration (CWE-204) the response is indistinguishable from the one
     * returned for a wrong password: the failure reason is always
     * {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH}, never
     * {@link AuthenticationFailureReason#USER_NOT_FOUND}, and a bind against a decoy DN is
     * attempted so that an unknown username costs roughly the same client-side directory round
     * trip as a known username with a wrong password. The outcome of that bind is ignored.
     * The decoy DN is {@link LdapConfiguration.SearchConfiguration#getDecoyDn()} when configured,
     * otherwise a random, non-existent entry under the search base.
     * <p>
     * Only the client-side cost is equalised. A directory may still answer faster for a
     * non-existent DN than for a wrong password; configure a real decoy entry where that matters.
     *
     * @param requestContext        The request context
     * @param authenticationRequest The authentication request, whose identity matched no entry
     * @return a {@link AuthenticationFailureReason#CREDENTIALS_DO_NOT_MATCH} failure
     * @since 5.5.2
     */
    @Experimental
    protected AuthenticationResponse rejectUnknownUser(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        DirContext decoyContext = null;
        try {
            decoyContext = contextBuilder.build(configuration.getSettings(decoyDn(), authenticationRequest.getSecret().toString()));
        } catch (javax.naming.AuthenticationException e) {
            debug(LOG, "Decoy bind for unknown user failed as expected. Encountered {}", e.getMessage());
        } catch (NamingException e) {
            // Anything other than invalid credentials means the decoy bind never reached the directory
            // or was rejected before the password was checked, so the mitigation is not doing its job.
            if (LOG.isWarnEnabled()) {
                LOG.warn("Decoy bind for unknown user failed with {} rather than invalid credentials; check [{}.{}.search.decoy-dn]. Encountered {}",
                    e.getClass().getSimpleName(), LdapConfiguration.PREFIX, configuration.getName(), e.getMessage());
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
     * No-op. The provider holds no resources that require closing; this method is retained for binary compatibility.
     *
     * @deprecated The provider holds no resources that require closing.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    @Override
    public void close() {
        // No op
    }
}
