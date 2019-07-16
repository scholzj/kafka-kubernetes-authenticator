package io.strimzi.kafka.kubernetes.authenticator;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class KubernetesTokenValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(KubernetesTokenValidatorCallbackHandler.class);

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        log.warn("Configuring the handler for SASL mechanism: {}", saslMechanism);

        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))    {
            log.warn("Unexpected SASL mechanism: {}", saslMechanism);
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        }

        for (Map.Entry entry : configs.entrySet()) {
            log.warn("Kafka config option {}: {}", entry.getKey(), entry.getValue());
        }

        for (AppConfigurationEntry entry : jaasConfigEntries) {
            for (Map.Entry entry2 : entry.getOptions().entrySet()) {
                log.warn("Jaas config options {}: {}", entry2.getKey(), entry2.getValue());
            }
        }
    }

    @Override
    public void close() {

    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException, IOException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback) {
                handleCallback((OAuthBearerValidatorCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    private void handleCallback(OAuthBearerValidatorCallback callback) throws IOException {
        log.warn("Callback {}", callback);
        log.warn("Callback client token value {}", callback.tokenValue());
        log.warn("Callback client token {}", callback.token());

        if (callback.tokenValue() == null) {
            throw new IllegalArgumentException("Callback has null token value!");
        }

        OAuthBearerTokenImpl token = new OAuthBearerTokenImpl(callback.tokenValue());
        log.warn("Got client token {}", token.toString());

        if (Time.SYSTEM.milliseconds() > token.lifetimeMs())    {
            log.warn("The token expired at {}", token.lifetimeMs());
            callback.error("The token is expired", null, "expired_token");
        }

        callback.token(token);
    }
}
