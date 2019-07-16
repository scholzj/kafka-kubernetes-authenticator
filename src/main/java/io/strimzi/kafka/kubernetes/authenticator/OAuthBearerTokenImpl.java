package io.strimzi.kafka.kubernetes.authenticator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

public class OAuthBearerTokenImpl implements OAuthBearerToken {
    private final String value;
    private final long  lifetimeMs;
    private final Long startTimeMs;
    private final String principalName;
    private final Set<String> scope;

    public OAuthBearerTokenImpl(String token) {
        Jwt<Header, Claims> jwsToken = Jwts.parser().parseClaimsJwt(stripSignature(token));
        Claims claims = jwsToken.getBody();

        this.value = token;
        this.principalName = claims.getSubject();
        this.lifetimeMs = parseExpiration(claims.getExpiration());
        this.startTimeMs = parseStartTime(claims.getIssuedAt());
        this.scope = parseScope(claims);
    }

    private String stripSignature(String token) {
        int i = token.lastIndexOf('.');
        return token.substring(0, i+1);
    }

    private long parseExpiration(Date expiration)  {
        if (expiration != null)   {
            return expiration.getTime();
        } else {
            return Long.MAX_VALUE;
        }
    }

    private long parseStartTime(Date startTime)  {
        if (startTime != null)   {
            return startTime.getTime();
        } else {
            return 0;
        }
    }

    private Set<String> parseScope(Claims claims) {
        Set<String> scope = new TreeSet<String>();
        Object maybeScope = claims.get("scope");

        if (maybeScope instanceof String)    {
            scope.addAll(Arrays.asList(((String) maybeScope).split(" ")));
        }

        return scope;
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
