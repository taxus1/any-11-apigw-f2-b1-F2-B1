package com.apigw.proxy.userauth;

import com.apigw.common.web.GatewayHeaders;
import com.apigw.domain.userauth.UserIdentity;
import com.apigw.domain.userauth.UserTokenVerifier;
import com.apigw.support.JwtMinter;
import com.apigw.support.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 守门人两入口的口径一致性（受保护 {@code verify} / 开放 {@code tryVerifyIdentity}）。
 *
 * 针对线上事故：同一枚过期令牌，受保护路由拦下之后，开放路由还把旧结论当有效身份
 * 透传给上游，两边说法对不上。根子是两套缓存两个窗口；收成一套之后，这里钉死：
 * 同一枚令牌在同一时刻，两个入口的判定必然一致——过期前一起认，压点一起不认，
 * 不管结论是从哪个入口暖进缓存的。
 */
class UserAuthGatekeeperTest {

    private static final String SECRET = "gatekeeper-test-token-secret-0123456789ab";
    private static final Instant T0 = Instant.parse("2027-06-01T00:00:00Z");
    private static final long T0_EPOCH = T0.getEpochSecond();

    private final MutableClock clock = MutableClock.at(T0);
    private UserAuthGatekeeper gatekeeper;

    @BeforeEach
    void setUp() {
        var verifier = new UserTokenVerifier(SECRET, null, clock, new ObjectMapper());
        gatekeeper = new UserAuthGatekeeper(verifier, null, clock);
    }

    private String tokenExpiringAt(long expEpochSecond) {
        return JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":" + expEpochSecond + "}");
    }

    private ServerHttpRequest requestWith(String token) {
        return MockServerHttpRequest.get("/open/1")
                .header(GatewayHeaders.AUTHORIZATION_HEADER, "Bearer " + token)
                .build();
    }

    @Test
    void sameToken_sameMoment_bothEntriesAgree_beforeAndAfterExpiry() {
        String token = tokenExpiringAt(T0_EPOCH + 30);

        // 过期前：两个入口都认，身份一致
        assertThat(gatekeeper.verify(token).ok()).isTrue();
        UserIdentity open = gatekeeper.tryVerifyIdentity(requestWith(token));
        assertThat(open).isNotNull();
        assertThat(open.userId()).isEqualTo("user-1");

        // 拨过过期点：同一时刻两个入口一起翻转，谁也不许多认一阵
        clock.advanceSeconds(31);
        assertThat(gatekeeper.verify(token).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNull();
    }

    @Test
    void protectedEntryWarmsCache_openEntryMustNotSeeIdentityAfterExp() {
        String token = tokenExpiringAt(T0_EPOCH + 30);

        // 受保护入口先验过（「通过」进缓存）
        assertThat(gatekeeper.verify(token).ok()).isTrue();

        // 缓存窗口还远没结束，但令牌已过期：开放入口不许把旧结论当有效身份透传
        clock.advanceSeconds(31);
        assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNull();
    }

    @Test
    void openEntryWarmsCache_protectedEntryMustRejectAfterExp() {
        String token = tokenExpiringAt(T0_EPOCH + 30);

        // 开放入口先验过（「通过」进缓存）
        assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNotNull();

        // 令牌过期后受保护入口必须拦：不能拿开放入口暖的缓存放行
        clock.advanceSeconds(31);
        assertThat(gatekeeper.verify(token).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
    }

    @Test
    void exactlyAtExpiry_bothEntriesTreatAsExpired() {
        // 正好压在过期那一刻：两个入口都按过期处理，没有「压点还能用」的缝
        String token = tokenExpiringAt(T0_EPOCH + 30);
        clock.advanceSeconds(30);

        assertThat(gatekeeper.verify(token).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNull();
    }

    @Test
    void repeatedArrivalsAcrossBothEntries_verdictsStayConsistent() {
        String token = tokenExpiringAt(T0_EPOCH + 30);

        // 同一枚令牌交替打两个入口：过期前每一次都认
        for (int i = 0; i < 3; i++) {
            assertThat(gatekeeper.verify(token).ok()).isTrue();
            assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNotNull();
            clock.advanceSeconds(5);
        }

        // 拨过过期点：之后每一次都不认，两个入口无一例外
        clock.advanceSeconds(20);
        for (int i = 0; i < 3; i++) {
            assertThat(gatekeeper.verify(token).ok()).isFalse();
            assertThat(gatekeeper.tryVerifyIdentity(requestWith(token))).isNull();
            clock.advanceSeconds(5);
        }
    }
}
