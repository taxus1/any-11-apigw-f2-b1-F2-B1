package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.GatewayPassSigner;
import com.apigw.domain.userauth.UserIdentity;
import com.apigw.domain.userauth.UserTokenVerifier;
import com.apigw.support.JwtMinter;
import com.apigw.support.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 守门人单元测试：受保护路由（{@link UserAuthGatekeeper#verify}）与开放路由
 * （{@link UserAuthGatekeeper#tryVerifyIdentity}）必须共用同一套结论缓存、同一口径——
 * 同一枚令牌在同一时刻不能一处认一处不认；区别只在失败时开放路由按匿名放行而非 401。
 */
class UserAuthGatekeeperTest {

    private static final String SECRET = "gatekeeper-test-token-secret-0123456789ab";
    private static final Instant START = Instant.parse("2027-05-01T08:00:00Z");
    private static final long START_EPOCH = START.getEpochSecond();

    private final MutableClock clock = new MutableClock(START);
    private final UserTokenVerifier verifier =
            new UserTokenVerifier(SECRET, null, clock, new ObjectMapper());
    private final UserAuthGatekeeper gatekeeper =
            new UserAuthGatekeeper(verifier, new GatewayPassSigner(SECRET), clock);

    private String token(long expEpochSecond) {
        return JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":" + expEpochSecond + "}");
    }

    private ServerHttpRequest requestWith(String token) {
        return MockServerHttpRequest.get("/open/1")
                .header("Authorization", "Bearer " + token)
                .build();
    }

    private ServerHttpRequest requestWithoutToken() {
        return MockServerHttpRequest.get("/open/1").build();
    }

    @Test
    void bothEntries_shareOneVerdict_whileTokenValid() {
        // 先在开放入口验过（身份透传），受保护入口同刻命中同一结论（通过）；反复交叉到达一致
        String t = token(START_EPOCH + 3600);

        UserIdentity identity = gatekeeper.tryVerifyIdentity(requestWith(t));
        assertThat(identity).isNotNull();
        assertThat(identity.userId()).isEqualTo("user-1");

        assertThat(gatekeeper.verify(t).ok()).isTrue();
        UserIdentity again = gatekeeper.tryVerifyIdentity(requestWith(t));
        assertThat(again).isEqualTo(identity);
        assertThat(gatekeeper.verify(t).ok()).isTrue();
    }

    @Test
    void bothEntries_rejectAtTheSameInstant_afterExpiry() {
        // 本次事故场景：令牌过期前在开放入口验过并缓存，过期那一刻两个入口必须同时改口——
        // 受保护入口判失败（401），开放入口给匿名（不再把旧身份透给上游）
        String t = token(START_EPOCH + 10);

        assertThat(gatekeeper.tryVerifyIdentity(requestWith(t))).isNotNull();
        assertThat(gatekeeper.verify(t).ok()).isTrue();

        clock.advanceSeconds(10);
        UserTokenVerifier.Result protectedVerdict = gatekeeper.verify(t);
        assertThat(protectedVerdict.ok()).isFalse();
        assertThat(protectedVerdict.failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);

        UserIdentity openIdentity = gatekeeper.tryVerifyIdentity(requestWith(t));
        assertThat(openIdentity).isNull();
    }

    @Test
    void protectedEntry_failingFirst_thenOpenEntry_doesNotStaleAccept() {
        // 反向也一致：令牌先过期，无论先到哪个入口，结论都不能分叉
        String t = token(START_EPOCH - 1);
        assertThat(gatekeeper.verify(t).ok()).isFalse();
        assertThat(gatekeeper.tryVerifyIdentity(requestWith(t))).isNull();
    }

    @Test
    void openEntry_withoutOrMalformedToken_isAnonymous() {
        assertThat(gatekeeper.tryVerifyIdentity(requestWithoutToken())).isNull();
        assertThat(gatekeeper.tryVerifyIdentity(requestWith("not-a-jwt"))).isNull();
        // scheme 不是 Bearer 也按没带令牌处理
        ServerHttpRequest basic = MockServerHttpRequest.get("/open/1")
                .header("Authorization", "Basic dXNlcjpwYXNz")
                .build();
        assertThat(gatekeeper.tryVerifyIdentity(basic)).isNull();
    }

    @Test
    void gatekeeperWithoutVerifier_openEntryAlwaysAnonymous() {
        UserAuthGatekeeper disabled = new UserAuthGatekeeper(null, null, clock);
        assertThat(disabled.tokenVerificationEnabled()).isFalse();
        assertThat(disabled.tryVerifyIdentity(requestWith(token(START_EPOCH + 3600)))).isNull();
    }
}
