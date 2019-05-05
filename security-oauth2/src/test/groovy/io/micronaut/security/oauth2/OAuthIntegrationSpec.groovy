package io.micronaut.security.oauth2;/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import io.micronaut.context.ApplicationContext;
import org.testcontainers.containers.DockerComposeContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * @author James Kleeh
 * @since
 */
public class OAuthIntegrationSpec {

    protected static GenericContainer hydra = new GenericContainer("oryd/hydra:v1.0.0-rc.11")
            .withEnv([
                    URLS_SELF_ISSUER: 'http://localhost:4444',
                    URLS_CONSENT: 'http://localhost:3000/consent',
                    URLS_LOGIN: 'http://localhost:3000/login',
                    URLS_LOGOUT: 'http://localhost:3000/logout',
                    LOG_LEVEL: 'debug',
                    DSN: 'memory',
                    SECRETS_SYSTEM: 'youReallyNeedToChangeThis',
                    OIDC_SUBJECT_IDENTIFIERS_ENABLED: 'public,pairwise',
                    OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT: 'youReallyNeedToChangeThis'
            ])
            .withCommand('serve all --dangerous-force-http')
            .waitingFor(new LogMessageWaitStrategy().withRegEx("(?s).*Starting server on :4444*"))

    protected static GenericContainer consent = new GenericContainer("oryd/hydra-login-consent-node:v1.0.0-rc.10")
            .withEnv([
                    HYDRA_ADMIN_URL: 'http://localhost:4445'
            ])
            .withCommand('serve all --dangerous-force-http')
            .waitingFor(new LogMessageWaitStrategy().withRegEx("(?s).*Listening on port 3000*"))


    static {
        hydra.setPortBindings(["4444:4444/tcp", "4445:4445/tcp"])
        hydra.start()
        hydra.execInContainer("hydra clients create --endpoint http://127.0.0.1:4445 --id auth-code-client --secret secret --grant-types authorization_code --response-types code --scope openid,offline --callbacks http://localhost:8085/oauth/callback/hydra --skip-tls-verify")
        consent.setPortBindings(["3000:3000/tcp"])
        consent.start()
    }

    protected ApplicationContext startContext() {
        return ApplicationContext.run(getConfiguration(), "test")
    }

    protected Map<String, Object> getConfiguration() {
        Map<String, Object> config = new HashMap<>()
        config.put("micronaut.server.port", 8085)
        config.put("spec.name", this.getClass().getSimpleName())
        return config
    }

}
