package com.apigw.domain.userauth;

import com.apigw.support.JwtMinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 用户令牌校验器单元测试（固定时钟，不依赖 Spring）。
 *
 * 核心立场：验签是真验签，不是把令牌拆开看字段。这里专门造各种「看着像、其实假」的令牌——
 * 错密钥签名、改载荷留旧签名、alg=none、别的算法、把「不过期」字样/超大数塞进 exp——
 * 每一个都必须被识破；过期边界卡到秒：now >= exp 即过期，压点也算过期，零宽限。
 */
class UserTokenVerifierTest {

    private static final String SECRET = "unit-test-token-secret-0123456789abcdef";
    private static final String OTHER_SECRET = "attacker-does-not-know-the-real-secret!!";
    private static final Instant NOW = Instant.parse("2027-01-15T00:00:00Z");
    private static final long NOW_EPOCH = NOW.getEpochSecond();

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final UserTokenVerifier verifier =
            new UserTokenVerifier(SECRET, null, clock, new ObjectMapper());

    private String payload(long exp, String sub, String tenant) {
        return "{\"sub\":\"" + sub + "\",\"tenant\":\"" + tenant + "\",\"exp\":" + exp + "}";
    }

    private String validToken() {
        return JwtMinter.mintHs256(SECRET, payload(NOW_EPOCH + 3600, "user-1", "tenant-a"));
    }

    @Test
    void validToken_passes_andYieldsIdentity() {
        UserTokenVerifier.Result r = verifier.verify(validToken());
        assertThat(r.ok()).isTrue();
        assertThat(r.identity().userId()).isEqualTo("user-1");
        assertThat(r.identity().tenantId()).isEqualTo("tenant-a");
    }

    @Test
    void okResult_carriesTokenExp_asHardBoundForConclusionReuse() {
        // 「通过」结论必须带上令牌自己的 exp：结论缓存拿它当复用的硬上限，
        // 复用窗口再大也不许越过过期那一刻
        long exp = NOW_EPOCH + 3600;
        UserTokenVerifier.Result r = verifier.verify(
                JwtMinter.mintHs256(SECRET, payload(exp, "user-1", "tenant-a")));
        assertThat(r.ok()).isTrue();
        assertThat(r.expEpochSeconds()).isEqualTo(exp);
    }

    @Test
    void forgedSignature_signedWithWrongSecret_isRejected() {
        // 攻击者不知道真密钥，拿自己的密钥签了一张「字段全对」的令牌
        String forged = JwtMinter.mintHs256(OTHER_SECRET, payload(NOW_EPOCH + 3600, "user-1", "tenant-a"));
        UserTokenVerifier.Result r = verifier.verify(forged);
        assertThat(r.ok()).isFalse();
        assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.BAD_SIGNATURE);
    }

    @Test
    void tamperedPayload_withOriginalSignature_isRejected() {
        // 把 sub 从 user-1 改成 admin，签名沿用原来的——重算签名对不上
        String original = validToken();
        String[] parts = original.split("\\.");
        String tamperedPayload = JwtMinter.b64url(payload(NOW_EPOCH + 3600, "admin", "tenant-a"));
        String tampered = JwtMinter.assemble(parts[0], tamperedPayload, parts[2]);
        UserTokenVerifier.Result r = verifier.verify(tampered);
        assertThat(r.ok()).isFalse();
        assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.BAD_SIGNATURE);
    }

    @Test
    void algNone_isRejected() {
        // 经典绕过：alg=none + 空签名段
        String header = JwtMinter.b64url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = JwtMinter.b64url(payload(NOW_EPOCH + 3600, "admin", "tenant-a"));
        assertThat(verifier.verify(header + "." + payload + ".").ok()).isFalse();
        // 带个假签名段也不行：算法本身就不接受
        UserTokenVerifier.Result r = verifier.verify(header + "." + payload + ".ZmFrZQ");
        assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.ALG_REJECTED);
    }

    @Test
    void otherAlgorithms_areRejected() {
        // 算法钉死 HS256：HS512、RS256、大小写变体一律拒
        String hs512 = JwtMinter.mint(SECRET, "{\"alg\":\"HS512\"}", payload(NOW_EPOCH + 3600, "u", "t"));
        assertThat(verifier.verify(hs512).failure()).isEqualTo(UserTokenVerifier.Failure.ALG_REJECTED);

        String lower = JwtMinter.mint(SECRET, "{\"alg\":\"hs256\"}", payload(NOW_EPOCH + 3600, "u", "t"));
        assertThat(verifier.verify(lower).failure()).isEqualTo(UserTokenVerifier.Failure.ALG_REJECTED);
    }

    @Test
    void expiryBoundary_exactlyAtExp_isExpired_noGracePeriod() {
        // 正好压在过期那一刻：按过期处理，没有「过期后还能用一小会儿」的缝
        String atBoundary = JwtMinter.mintHs256(SECRET, payload(NOW_EPOCH, "user-1", "tenant-a"));
        UserTokenVerifier.Result r = verifier.verify(atBoundary);
        assertThat(r.ok()).isFalse();
        assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);

        // 前一秒当然更过期
        String past = JwtMinter.mintHs256(SECRET, payload(NOW_EPOCH - 1, "user-1", "tenant-a"));
        assertThat(verifier.verify(past).failure()).isEqualTo(UserTokenVerifier.Failure.EXPIRED);

        // 后一秒还活着
        String alive = JwtMinter.mintHs256(SECRET, payload(NOW_EPOCH + 1, "user-1", "tenant-a"));
        assertThat(verifier.verify(alive).ok()).isTrue();
    }

    @Test
    void expWrittenAsNeverKeyword_isRejected() {
        // 把「不过期」字样塞进 exp 冒充永不过期：类型不对，直接拒
        String token = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":\"never\"}");
        UserTokenVerifier.Result r = verifier.verify(token);
        assertThat(r.ok()).isFalse();
        assertThat(r.failure()).isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
    }

    @Test
    void expAsOverflowingHugeNumber_isRejected() {
        // 塞一个超出 long 的超大数冒充「永远不到」：放不进 long 就不认
        String token = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":99999999999999999999999999}");
        assertThat(verifier.verify(token).failure()).isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
    }

    @Test
    void missingExp_isRejected() {
        String token = JwtMinter.mintHs256(SECRET, "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\"}");
        assertThat(verifier.verify(token).failure()).isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);
    }

    @Test
    void missingUserOrTenant_isRejected() {
        String noSub = JwtMinter.mintHs256(SECRET, "{\"tenant\":\"tenant-a\",\"exp\":" + (NOW_EPOCH + 60) + "}");
        assertThat(verifier.verify(noSub).failure()).isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);

        String noTenant = JwtMinter.mintHs256(SECRET, "{\"sub\":\"user-1\",\"exp\":" + (NOW_EPOCH + 60) + "}");
        assertThat(verifier.verify(noTenant).failure()).isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);

        String blankSub = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"  \",\"tenant\":\"tenant-a\",\"exp\":" + (NOW_EPOCH + 60) + "}");
        assertThat(verifier.verify(blankSub).failure()).isEqualTo(UserTokenVerifier.Failure.MISSING_CLAIM);
    }

    @Test
    void identityValueWithInjectionChars_isRejected() {
        // 签名是真的，但 sub 里塞了换行（想借身份头做响应拆分）：白名单拦住
        String token = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\\r\\nX-Evil: 1\",\"tenant\":\"tenant-a\",\"exp\":" + (NOW_EPOCH + 60) + "}");
        assertThat(verifier.verify(token).failure()).isEqualTo(UserTokenVerifier.Failure.CLAIM_INVALID);
    }

    @Test
    void notBeforeInFuture_isRejected() {
        String token = JwtMinter.mintHs256(SECRET,
                "{\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"nbf\":" + (NOW_EPOCH + 300)
                        + ",\"exp\":" + (NOW_EPOCH + 3600) + "}");
        assertThat(verifier.verify(token).failure()).isEqualTo(UserTokenVerifier.Failure.NOT_YET_VALID);
    }

    @Test
    void issuerMismatch_isRejected_whenIssuerConfigured() {
        UserTokenVerifier withIssuer =
                new UserTokenVerifier(SECRET, "apigw", clock, new ObjectMapper());
        String wrongIss = JwtMinter.mintHs256(SECRET,
                "{\"iss\":\"someone-else\",\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":"
                        + (NOW_EPOCH + 60) + "}");
        assertThat(withIssuer.verify(wrongIss).failure())
                .isEqualTo(UserTokenVerifier.Failure.ISSUER_MISMATCH);

        String rightIss = JwtMinter.mintHs256(SECRET,
                "{\"iss\":\"apigw\",\"sub\":\"user-1\",\"tenant\":\"tenant-a\",\"exp\":"
                        + (NOW_EPOCH + 60) + "}");
        assertThat(withIssuer.verify(rightIss).ok()).isTrue();
    }

    @Test
    void malformedTokens_areRejected() {
        assertThat(verifier.verify(null).ok()).isFalse();
        assertThat(verifier.verify("").ok()).isFalse();
        assertThat(verifier.verify("only.two").ok()).isFalse();
        assertThat(verifier.verify("a.b.c.d").ok()).isFalse();
        // 签名段不是合法 base64url
        assertThat(verifier.verify("a.b.!!!").ok()).isFalse();
        // 载荷不是 JSON
        String notJson = JwtMinter.mint(SECRET, "{\"alg\":\"HS256\"}", "this-is-not-json");
        assertThat(verifier.verify(notJson).ok()).isFalse();
        // 超长令牌
        assertThat(verifier.verify("x".repeat(9000)).ok()).isFalse();
    }

    @Test
    void blankBearerContent_isRejected() {
        assertThat(verifier.verify("   ").ok()).isFalse();
    }
}
