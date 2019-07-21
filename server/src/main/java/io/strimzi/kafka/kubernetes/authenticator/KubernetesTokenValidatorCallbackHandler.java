package io.strimzi.kafka.kubernetes.authenticator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fabric8.kubernetes.api.model.authentication.TokenReview;
import io.fabric8.kubernetes.api.model.authentication.TokenReviewBuilder;
import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.OperationSupport;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
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
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))    {
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
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
        if (callback.tokenValue() == null) {
            throw new IllegalArgumentException("Callback has null token value!");
        }

        OAuthBearerTokenImpl token = new OAuthBearerTokenImpl(callback.tokenValue());

        if (Time.SYSTEM.milliseconds() > token.lifetimeMs())    {
            log.trace("The token expired at {}", token.lifetimeMs());
            callback.error("expired_token", null, null);
        }

        validateToken(token.value(), callback);

        if (callback.errorStatus() == null) {
            // No errors during the validation
            // We can set the token to indicate success
            callback.token(token);
        }
    }

    private void validateToken(String token, OAuthBearerValidatorCallback callback) throws IOException {
        try {
            KubernetesClient client = new DefaultKubernetesClient();
            OkHttpClient okClient = client.adapt(OkHttpClient.class);

            TokenReview tokenReview = new TokenReviewBuilder()
                    .withNewSpec()
                    .withNewToken(token)
                    .endSpec()
                    .build();

            RequestBody body = RequestBody.create(OperationSupport.JSON, new ObjectMapper().writeValueAsString(tokenReview));

            Response response = okClient.newCall(new Request.Builder().post(body).url(client.getMasterUrl().toString() + "apis/" + tokenReview.getApiVersion()
                    + "/tokenreviews").build()).execute();
            ResponseBody responseBody = response.body();

            if (response.code() == 201
                    && responseBody != null) {
                String responseBodyString = responseBody.string();

                log.trace("Received TokenReview repsonse: {}", responseBodyString);
                TokenReview review = new ObjectMapper().readValue(responseBodyString, TokenReview.class);

                if (review.getStatus() != null
                        && (review.getStatus().getAuthenticated() == null || !review.getStatus().getAuthenticated())) {
                    if (review.getStatus() != null
                            && review.getStatus().getError() != null) {
                        log.debug("Token is not authenticated: {}", review.getStatus().getError());
                    } else {
                        log.debug("Token is not authenticated");
                    }

                    callback.error("invalid_token", null, null);
                } else if (review.getStatus() != null
                        && review.getStatus().getAuthenticated() != null
                        && review.getStatus().getAuthenticated()) {
                    log.debug("Token is authenticated as {}", review.getStatus().getUser());
                } else {
                    log.warn("Failed to parse TokenReview response.");
                    callback.error("invalid_token", null, null);
                }

                response.close();
            } else {
                log.warn("Failed to review the token. TokenReview returned HTTP {}.", response.code());
                response.close();
                callback.error("invalid_token", null, null);
                throw new IOException("Failed to review the token. TokenReview returned HTTP " + response.code());
            }
        } catch (JsonProcessingException e) {
            log.warn("Failed to review the token: {}", e);
            callback.error("invalid_token", null, null);
            throw new IOException(e);
        }


    }
}
