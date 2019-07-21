package io.strimzi.kafka.kubernetes.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

public class OAuthBearerTokenImpl implements OAuthBearerToken {
    private final String value;
    private final long  lifetimeMs;
    private final Long startTimeMs;
    private final String principalName;
    private final Set<String> scope;

    public OAuthBearerTokenImpl(String token) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        String base64Payload = getPayload(token);
        String payload = new String(Base64.getDecoder().decode(base64Payload));
        JsonNode jsonPayload = mapper.readTree(payload);

        this.value = token;
        this.principalName = parseSubject(jsonPayload.get("sub"));
        this.lifetimeMs = parseExp(jsonPayload.get("exp"));
        this.startTimeMs = parseIat(jsonPayload.get("iat"));
        this.scope = Collections.EMPTY_SET;
    }

    /*test*/ static String getPayload(String token) {
        int first = token.indexOf('.');
        int last = token.lastIndexOf('.');

        return token.substring(first+1, last);
    }

    private static String parseSubject(JsonNode subject) throws IOException   {
        if (subject == null)    {
            throw new IOException("The token does not contain subject.");
        } else if (JsonNodeType.STRING.equals(subject.getNodeType()))  {
            return subject.asText();
        } else {
            throw new IOException("The subject has unexpected type " + subject.getNodeType() + ".");
        }
    }

    private static long parseIat(JsonNode iat) throws IOException   {
        if (iat == null)    {
            return 0;
        } else if (JsonNodeType.NUMBER.equals(iat.getNodeType()))  {
            return iat.asLong();
        } else {
            return 0;
        }
    }

    private static long parseExp(JsonNode exp) throws IOException   {
        if (exp == null)    {
            return Long.MAX_VALUE;
        } else if (JsonNodeType.NUMBER.equals(exp.getNodeType()))  {
            return exp.asLong();
        } else {
            return Long.MAX_VALUE;
        }
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Set<String> scope() {
        return scope;
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs;
    }

    @Override
    public String toString() {
        return "OAuthBearerTokenImpl{" +
                "value='" + value + '\'' +
                ", lifetimeMs=" + lifetimeMs +
                ", startTimeMs=" + startTimeMs +
                ", principalName='" + principalName + '\'' +
                ", scope=" + scope +
                '}';
    }
}
