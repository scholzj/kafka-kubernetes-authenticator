package io.strimzi.kafka.kubernetes.authenticator;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.junit.Test;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class OAuthBearerTokenImplTest {
    private static String SAMPLE_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi1ydHE2ayIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZjgwYjU0YTktYTcxMC0xMWU5LTg1NzEtMzIxZjFhYzFmNTlkIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Om15cHJvamVjdDpkZWZhdWx0In0.RqZUxOpOfjkwNn2doM2XlIeVouo6WXBV9Noqj3H-HxfArZC44S29GBhGLc-KFyrTgb_n6OILf9ZS9birY3KjmoS_DnHP17JLrL96AAuKsGusYEWzjmUIoqaN1PA81_ueiIx7WM1McBq0oxyOfNyi_j1oyhudjijl4CXZ3yFJdgaNFuGr10dbBhktelqjvAcyFsqw01A8ZS1UwXayZGK_XUSaJA2vDinjKxKkFroR-rMjaOlAejBgidctgAsgJScTdhv-L1olrgIxp_h9g4NEGEfXqHNAcnPgKKMag_4xUNIdZGnfsDpVKfHPJCj620rTZTg7TpR0BVw20M0kOZBnUw";

    @Test
    public void testGetPayload()    {
        String payload = "eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi1ydHE2ayIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZjgwYjU0YTktYTcxMC0xMWU5LTg1NzEtMzIxZjFhYzFmNTlkIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Om15cHJvamVjdDpkZWZhdWx0In0";
        assertEquals(payload, OAuthBearerTokenImpl.getPayload(SAMPLE_TOKEN));
    }

    @Test
    public void testTokenDecoding() throws IOException {
        OAuthBearerToken token = new OAuthBearerTokenImpl(SAMPLE_TOKEN);

        assertEquals(Long.MAX_VALUE, token.lifetimeMs());
        assertEquals(new Long(0), token.startTimeMs());
        assertEquals("system:serviceaccount:myproject:default", token.principalName());
        assertEquals(SAMPLE_TOKEN, token.value());
        assertEquals(Collections.EMPTY_SET, token.scope());
    }
}
