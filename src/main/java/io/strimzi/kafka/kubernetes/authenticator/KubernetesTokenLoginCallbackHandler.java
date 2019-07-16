package io.strimzi.kafka.kubernetes.authenticator;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

public class KubernetesTokenLoginCallbackHandler implements AuthenticateCallbackHandler {
    private static final String KUBERNETES_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private static final Logger log = LoggerFactory.getLogger(KubernetesTokenLoginCallbackHandler.class);

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
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback) {
                handleCallback((OAuthBearerTokenCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    private void handleCallback(OAuthBearerTokenCallback callback) throws IOException {
        if (callback.token() != null) {
            throw new IllegalArgumentException("Callback had a token already");
        }

        callback.token(getToken());
    }

    private OAuthBearerToken getToken() throws IOException {
        //String token = new String(Files.readAllBytes(Paths.get(KUBERNETES_TOKEN_PATH)));
        String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoic3RyaW16aS1jbHVzdGVyLW9wZXJhdG9yLXRva2VuLXE5Z2Q4Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6InN0cmltemktY2x1c3Rlci1vcGVyYXRvciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjI4YmQxN2U3LWE3ZjctMTFlOS05YzA2LTMyMWYxYWMxZjU5ZCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpteXByb2plY3Q6c3RyaW16aS1jbHVzdGVyLW9wZXJhdG9yIn0.VUut5rtG4tAheJj33LiK5qhd4dFaS7E9bXGbkn2Hf5I2p3qyc-C5ise1fy37mgTo1wW9cP188UQb-rqn7MEbR3rELMbBP42UgI5eE8kybr-MUvyDABElqEXlvuLt_yPLNOlZEhvv2X4b_Y9papj7dx4YKO-MEeHzfKnhdV4R2PUwEtU6RyvfXDkDrTTRlhdEzlVo_5vdemyaEvw4Epfu0yGKH4ZQAgRkTfuB0d08o9HvUcsRLCJxdFM6eaqepN2gfo5DK2rZNgoDBWl-ny5-ZoqKlY4x-5rN52e3Av_VgRGMrLA-SbVq7u6s6n_0g0ILFQREsfdJaJuvWf8mFQ_h9A";
        OAuthBearerToken oAuthToken = new OAuthBearerTokenImpl(token);
        log.warn("Got client token {}", oAuthToken.toString());
        return oAuthToken;
    }
}
