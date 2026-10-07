package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.UserTokenVerifier;
import com.apigw.support.JwtMinter;
import com.apigw.support.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 验签结论缓存的复用纪律（真实验签器 + 可拨动时钟，不依赖 Spring）。
 *
 * 针对线上事故：令牌过期后，缓存的「通过」结论仍被复用到窗口结束——受保护路由
 * 过期后还能进一阵。这里把纪律钉死：
 * - 复用窗口恰好跨过过期点：exp 一到，旧结论立即作废，压点那一刻就按过期判；
 * - 同一枚令牌反复到达：窗口内只真验一次（缓存确实省了验签）；
 * - 确定型失败（缺 exp、exp 类型不对、已过期）窗口内复用；
 * - nbf 未到的结论不留：到点即翻转成通过，不被旧结论多挡一阵；
 * - 窗口外一律重验；窗口配 0 等于不缓存。
 */
class IdentityCheckCacheTest {

    private static final String SECRET = "cache-test-token-secret-0123456789abcdef";
    private static final Instant T0 = Instant.parse("2027-06-01T00:00:00Z");
    private static final long T0_EPOCH = T0.getEpochSecond();
    private static final long WINDOW_MILLIS = 60_000L;

    private final MutableClock clock = MutableClock.at(T0);
    private final UserTokenVerifier verifier =
            new UserTokenVerifier(SECRET, null, clock, new ObjectMapper());
    private final AtomicInteger verifyCalls = new AtomicInteger();
    /** 包一层计数：真验几次一目了然（缓存省没省验签、作废及不及时都靠它断）。 */
    private final Function<String, UserTokenVerifier.Result> countingVerifier = token -> {
        verifyCalls.incrementAndGet();
        return verifier.verify(token);
    };

    private IdentityCheckCache cache;

    @BeforeEach
    void setUp() {
        cache = new IdentityCheckCache(WINDOW_MILLIS, clock);
    }

    private String tokenExpiringAt(long expEpochSecond) {
        return JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":" + expEpochSecond + "}");
    }

    @Test
    void sameTokenRepeatedArrivals_withinWindow_verifyOnlyOnce() {
        String token = tokenExpiringAt(T0_EPOCH + 3600);

        for (int i = 0; i < 5; i++) {
            UserTokenVerifier.Result r = cache.check(token, countingVerifier);
            assertThat(r.ok()).isTrue();
            assertThat(r.identity().userId()).isEqualTo("user-1");
        }
        assertThat(verifyCalls).hasValue(1);
    }

    @Test
    void reuseWindowStraddlingExpiry_cachedOkIsDroppedExactlyAtExp() {
        // 核心回归：窗口 60s，令牌 30s 后过期——窗口必然跨过过期点
        String token = tokenExpiringAt(T0_EPOCH + 30);

        assertThat(cache.check(token, countingVerifier).ok()).isTrue();
        assertThat(verifyCalls).hasValue(1);

        // 过期前 1 秒：仍在复用期内，直接命中
        clock.advanceSeconds(29);
        assertThat(cache.check(token, countingVerifier).ok()).isTrue();
        assertThat(verifyCalls).hasValue(1);

        // 正好压在过期那一刻：旧结论必须作废，重验并按过期判（窗口还剩 30s 也不许再认）
        clock.advanceSeconds(1);
        UserTokenVerifier.Result atBoundary = cache.check(token, countingVerifier);
        assertThat(atBoundary.ok()).isFalse();
        assertThat(atBoundary.failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifyCalls).hasValue(2);

        // 过期结论属确定型失败：窗口内复用，不再重复真验
        clock.advanceSeconds(1);
        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifyCalls).hasValue(2);
    }

    @Test
    void okReuseIsBoundedByTokenExp_evenWhenWindowIsHuge() {
        // 复用多久都得跟着令牌自己的有效期走：窗口开得再大也越不过 exp
        IdentityCheckCache hugeWindow = new IdentityCheckCache(3_600_000_000L, clock);
        String token = tokenExpiringAt(T0_EPOCH + 30);

        assertThat(hugeWindow.check(token, countingVerifier).ok()).isTrue();
        clock.advanceSeconds(30);
        assertThat(hugeWindow.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
    }

    @Test
    void expiredToken_failureIsReused_withinWindow_reverifiedAfterWindow() {
        String token = tokenExpiringAt(T0_EPOCH - 10);

        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        clock.advanceSeconds(30);
        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifyCalls).hasValue(1);

        // 窗口一过重新真验（结论当然还是过期）
        clock.advanceSeconds(31);
        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifyCalls).hasValue(2);
    }

    @Test
    void missingExpOrBadExpType_deterministicFailures_reusedWithinWindow() {
        String noExp = JwtMinter.mintHs256(SECRET, "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\"}");
        String expAsText = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":\"never\"}");

        assertThat(cache.check(noExp, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);
        assertThat(cache.check(expAsText, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
        assertThat(verifyCalls).hasValue(2);

        // 窗口内反复到达：确定型失败直接复用，不重复真验，口径不变
        clock.advanceSeconds(30);
        assertThat(cache.check(noExp, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);
        assertThat(cache.check(expAsText, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
        assertThat(verifyCalls).hasValue(2);
    }

    @Test
    void notYetValid_isNeverCached_flipsToAcceptedExactlyAtNbf() {
        String token = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"nbf\":" + (T0_EPOCH + 10)
                        + ",\"exp\":" + (T0_EPOCH + 3600) + "}");

        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.NOT_YET_VALID);

        // 没到点：每次都真验（这个结论会翻转，不许留）
        clock.advanceSeconds(5);
        assertThat(cache.check(token, countingVerifier).failure())
                .isEqualTo(UserTokenVerifier.Failure.NOT_YET_VALID);
        assertThat(verifyCalls).hasValue(2);

        // 一到生效时刻立即认：不被「还没到」的旧结论多挡一阵
        clock.advanceSeconds(5);
        assertThat(cache.check(token, countingVerifier).ok()).isTrue();
        assertThat(verifyCalls).hasValue(3);
    }

    @Test
    void okConclusion_isReverified_onceWindowElapses() {
        String token = tokenExpiringAt(T0_EPOCH + 3600);

        assertThat(cache.check(token, countingVerifier).ok()).isTrue();
        // 窗口结束（令牌还健在）：重新真验，结论照旧
        clock.advanceSeconds(61);
        assertThat(cache.check(token, countingVerifier).ok()).isTrue();
        assertThat(verifyCalls).hasValue(2);
    }

    @Test
    void zeroWindow_meansNoCaching_everyArrivalIsReallyVerified() {
        IdentityCheckCache noCache = new IdentityCheckCache(0, clock);
        String token = tokenExpiringAt(T0_EPOCH + 3600);

        assertThat(noCache.check(token, countingVerifier).ok()).isTrue();
        assertThat(noCache.check(token, countingVerifier).ok()).isTrue();
        assertThat(verifyCalls).hasValue(2);
        assertThat(noCache.size()).isZero();
    }
}
