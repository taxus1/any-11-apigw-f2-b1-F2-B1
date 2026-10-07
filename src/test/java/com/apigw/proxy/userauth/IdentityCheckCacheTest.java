package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.UserTokenVerifier;
import com.apigw.support.JwtMinter;
import com.apigw.support.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 验签结论短缓存的单元测试（可拨时钟，不依赖 Spring）。
 *
 * 回归这次的怪事：
 * - 成功结论的复用寿命被令牌自身 exp 截断，复用窗口再长也不越过过期那一刻（含压点）；
 * - 同一枚令牌反复到达只真验一次，但过期后下一笔立刻重新真验；
 * - 失败结论（含 nbf 未到、过期、缺/错 exp）一律不留，每笔真验，时间一到能自然翻盘；
 * - 窗口配 0 = 每次真验，结论完全不落缓存。
 */
class IdentityCheckCacheTest {

    private static final String SECRET = "cache-test-token-secret-0123456789abcdef";
    private static final Instant START = Instant.parse("2027-03-01T00:00:00Z");
    private static final long START_EPOCH = START.getEpochSecond();

    private final MutableClock clock = new MutableClock(START);
    private final UserTokenVerifier verifier =
            new UserTokenVerifier(SECRET, null, clock, new ObjectMapper());

    /** 包一层计数：每真验一次 +1，缓存命中不增，借此区分「复用」与「真验」。 */
    private final AtomicInteger verifications = new AtomicInteger();

    private IdentityCheckCache cache(long windowMillis) {
        return new IdentityCheckCache(windowMillis, clock);
    }

    private UserTokenVerifier.Result check(IdentityCheckCache cache, String token) {
        return cache.check(token, t -> {
            verifications.incrementAndGet();
            return verifier.verify(t);
        });
    }

    private String token(String payloadJson) {
        return JwtMinter.mintHs256(SECRET, payloadJson);
    }

    private String tokenExpiringAt(long expEpochSecond) {
        return token("{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":" + expEpochSecond + "}");
    }

    @Test
    void repeatedArrivals_withinWindow_verifyOnlyOnce_andKeepServing() {
        // 同一枚令牌反复到达：窗口内只真验一遍，后续全复用同一成功结论
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH + 3600);

        assertThat(check(cache, t).ok()).isTrue();
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(check(cache, t).ok()).isTrue();
        clock.advanceSeconds(30);
        assertThat(check(cache, t).ok()).isTrue();

        assertThat(verifications).hasValue(1);
        assertThat(cache.size()).isEqualTo(1);
    }

    @Test
    void windowCrossingExpiry_entryDiesAtExp_notAtWindowEnd() {
        // 复用窗口（60s）本可跨过 exp：令牌在 +10s 过期，+9s 还在窗口内但必须重新真验并判过期，
        // 绝不能把过期前缓存的 OK 结论用到过期之后（本次事故的核心场景）
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH + 10);

        assertThat(check(cache, t).ok()).isTrue();
        verifications.set(0);

        clock.advanceSeconds(5);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(0);

        // 正好压在过期那一刻：now == exp，按过期处理，缓存不得放行
        clock.advanceSeconds(5);
        UserTokenVerifier.Result atExpiry = check(cache, t);
        assertThat(atExpiry.ok()).isFalse();
        assertThat(atExpiry.failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifications).hasValue(1);

        // 过期后再来：仍是真验、仍拒绝，且失败不留缓存
        clock.advanceSeconds(10);
        assertThat(check(cache, t).ok()).isFalse();
        assertThat(verifications).hasValue(2);
        assertThat(cache.size()).isZero();
    }

    @Test
    void cachedEntryExpiringWithinSameSecond_isRecheckedAtBoundary() {
        // 起点后 300ms 缓存、令牌 1s 后过期：同秒内复用放行；拨到整秒边界立刻失效
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH + 1);

        assertThat(check(cache, t).ok()).isTrue();
        clock.advanceMillis(500);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(1);

        clock.advanceMillis(500);
        assertThat(check(cache, t).failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        assertThat(verifications).hasValue(2);
    }

    @Test
    void windowSlidingBeforeExpiry_reverifies_andCachesAgain() {
        // 窗口先于 exp 滑过：窗口一到就重新真验（仍然有效），新结论继续复用
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH + 3600);

        assertThat(check(cache, t).ok()).isTrue();
        clock.advanceMillis(60_000);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(2);

        clock.advanceSeconds(10);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(2);
    }

    @Test
    void expiredFailure_isNeverCached_everyRequestReverifies() {
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH - 10);

        for (int i = 0; i < 3; i++) {
            UserTokenVerifier.Result r = check(cache, t);
            assertThat(r.ok()).isFalse();
            assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);
        }
        // 失败不留：三笔全部真验
        assertThat(verifications).hasValue(3);
        assertThat(cache.size()).isZero();
    }

    @Test
    void badSignatureFailure_isNeverCached() {
        IdentityCheckCache cache = cache(60_000);
        String forged = JwtMinter.mintHs256("not-the-real-secret",
                "{\"sub\":\"u\",\"tenant\":\"t\",\"exp\":" + (START_EPOCH + 3600) + "}");

        for (int i = 0; i < 3; i++) {
            assertThat(check(cache, forged).failure())
                    .isEqualTo(UserTokenVerifier.Failure.BAD_SIGNATURE);
        }
        assertThat(verifications).hasValue(3);
        assertThat(cache.size()).isZero();
    }

    @Test
    void missingExp_andWrongTypedExp_areRejectedAndNeverCached() {
        IdentityCheckCache cache = cache(60_000);

        String noExp = token("{\"sub\":\"u\",\"tenant\":\"t\"}");
        for (int i = 0; i < 2; i++) {
            assertThat(check(cache, noExp).failure())
                    .isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);
        }
        assertThat(verifications).hasValue(2);
        assertThat(cache.size()).isZero();

        verifications.set(0);
        String stringExp = token("{\"sub\":\"u\",\"tenant\":\"t\",\"exp\":\"never\"}");
        for (int i = 0; i < 2; i++) {
            assertThat(check(cache, stringExp).failure())
                    .isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
        }
        assertThat(verifications).hasValue(2);
        assertThat(cache.size()).isZero();
    }

    @Test
    void notYetValid_flipsToAllowed_onceNbfArrives_becauseFailuresAreNotCached() {
        // nbf 在 +60s：先拒（NOT_YET_VALID），失败不缓存；时钟拨过 nbf 后下一笔真验即通过并缓存
        IdentityCheckCache cache = cache(60_000);
        String t = token("{\"sub\":\"u\",\"tenant\":\"t\",\"nbf\":" + (START_EPOCH + 60)
                + ",\"exp\":" + (START_EPOCH + 3600) + "}");

        assertThat(check(cache, t).failure()).isEqualTo(UserTokenVerifier.Failure.NOT_YET_VALID);
        assertThat(verifications).hasValue(1);

        clock.advanceSeconds(30);
        assertThat(check(cache, t).failure()).isEqualTo(UserTokenVerifier.Failure.NOT_YET_VALID);
        assertThat(verifications).hasValue(2);

        clock.advanceSeconds(30);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(3);

        // 之后走复用，不再真验
        clock.advanceSeconds(10);
        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(3);
    }

    @Test
    void zeroWindow_verifiesEveryTime_evenWhileValid() {
        IdentityCheckCache cache = cache(0);
        String t = tokenExpiringAt(START_EPOCH + 3600);

        for (int i = 0; i < 3; i++) {
            assertThat(check(cache, t).ok()).isTrue();
        }
        assertThat(verifications).hasValue(3);
        assertThat(cache.size()).isZero();
    }

    @Test
    void invalidate_dropsCachedConclusions() {
        // 模拟密钥轮换/停用：旧密钥下的成功结论必须被清干净，之后重新真验
        IdentityCheckCache cache = cache(60_000);
        String t = tokenExpiringAt(START_EPOCH + 3600);

        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(1);

        cache.invalidate();
        assertThat(cache.size()).isZero();

        assertThat(check(cache, t).ok()).isTrue();
        assertThat(verifications).hasValue(2);
    }
}
