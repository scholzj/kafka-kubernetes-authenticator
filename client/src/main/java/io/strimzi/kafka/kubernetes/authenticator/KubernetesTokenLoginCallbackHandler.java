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
    private static final Logger log = LoggerFactory.getLogger(KubernetesTokenLoginCallbackHandler.class);

    private static final String TOKEN_ENV_VAR = "OAUTHBEARER_TOKEN";
    private static final String TOKEN_FILE_ENV_VAR = "OAUTHBEARER_TOKEN_FILE";
    private static final String KUBERNETES_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private String providedToken = null;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))    {
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        }

        if (jaasConfigEntries.get(0).getOptions().containsKey("token")) {
            providedToken = (String) jaasConfigEntries.get(0).getOptions().get("token");
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
        String token;

        if (providedToken != null)   {
            log.debug("Using token from JAAS configuration");
            token = providedToken;
        } else if (System.getenv().containsKey(TOKEN_ENV_VAR)) {
            log.debug("Using token from environment variable {}", TOKEN_ENV_VAR);
            token = System.getenv().get(TOKEN_ENV_VAR);
        } else if (System.getenv().containsKey(TOKEN_FILE_ENV_VAR)) {
            log.debug("Using token from file {}", TOKEN_FILE_ENV_VAR);
            token = getTokenFromFile(TOKEN_FILE_ENV_VAR);
        } else {
            log.debug("Using token from file {}", KUBERNETES_TOKEN_PATH);
            token = getTokenFromFile(KUBERNETES_TOKEN_PATH);
        }

        OAuthBearerToken oAuthToken = new OAuthBearerTokenImpl(token);

        return oAuthToken;
    }

    private String getTokenFromFile(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }
}
