package com.apigw.domain.userauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;

/**
 * 自签用户令牌（JWT / JWS compact 形式，算法钉死 HS256）的校验器。
 *
 * 调用方把网关签发的令牌放在 {@code Authorization: Bearer <token>} 里带进来，
 * 网关在这里验三样，任何一样不过都判失败（失败原因只进服务端日志，调用方只拿到统一 401）：
 *
 * 1. <b>签名真不真</b>——不是把令牌拆开看字段就算数：
 *    - 用配置进来的 HMAC 密钥对「header.payload」重新算一遍 HMAC-SHA256，
 *      和令牌自带签名做常量时间比对（{@link MessageDigest#isEqual}），
 *      拿假签名、拿别的密钥签的、把载荷改过又保留旧签名的，全都识破；
 *    - 算法白名单钉死 {@code alg=HS256}：{@code none}（无签名）、HS512/RS256 等
 *      任何别的算法一律拒，从根上断了「改 alg 绕签名」这条路；
 *    - 签名段必须是合法 base64url 且长度非零。
 * 2. <b>过期没有</b>——{@code exp} 必须存在且是能放进 long 的整数秒；
 *    当前时刻 {@code now >= exp} 即过期，<b>正好压在过期那一刻按过期处理</b>，
 *    不做任何宽限，没有「过期后还能用一小会儿」的缝；
 *    {@code nbf}（生效时刻）存在时同样按秒卡（now &lt; nbf 拒）。
 * 3. <b>该有的信息全不全</b>——{@code sub}（用户标识）、{@code tenant}（租户标识）
 *    必须是非空白字符串且过身份白名单；把 {@code exp} 写成 "never" 这种「不过期」字样、
 *    或塞一个超出 long 的超大数冒充永不过期，都会因为类型不对被拒。
 *
 * 配置了 expectedIssuer 时另验 {@code iss} 必须与之一致。
 *
 * 密钥从配置进（见 {@code apigw.user-auth.*}），本类不内置任何默认密钥：
 * 没配密钥时这台网关就不该装配校验器，路由却要求登录的场景 fail-closed。
 */
public final class UserTokenVerifier {

    /** 唯一接受的签名算法：HMAC-SHA256。 */
    public static final String ALGORITHM = "HS256";

    /** 令牌长度硬上限，防有人用超大串拖垮解析/算签，超出当畸形。 */
    private static final int MAX_TOKEN_LENGTH = 8192;

    /** 载荷里的租户标识声明名（sub 是标准的主体/用户标识声明）。 */
    public static final String CLAIM_TENANT = "tenant";

    private final byte[] secret;
    private final String expectedIssuer;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    /**
     * @param secret         HMAC 密钥（配置传入，禁止硬编码）；非空
     * @param expectedIssuer 非空时强制校验 iss 声明；null 表示不校
     * @param clock          判过期用的时钟（生产系统 UTC 钟，测试可固定/拨动）
     * @param objectMapper   解析 header/payload JSON
     */
    public UserTokenVerifier(String secret, String expectedIssuer, Clock clock, ObjectMapper objectMapper) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("令牌校验密钥不能为空（请配置 apigw.user-auth.token-secret）");
        }
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.expectedIssuer = expectedIssuer == null || expectedIssuer.isBlank() ? null : expectedIssuer.trim();
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    /** 校验失败原因：只用于服务端日志，绝不回给调用方。 */
    public enum Failure {
        /** 令牌不是合法的三段 JWT、base64/JSON 解不开。 */
        MALFORMED,
        /** alg 不是钉死的 HS256（含 none 与其他算法）。 */
        ALG_REJECTED,
        /** 重新计算的签名和令牌自带的对不上。 */
        BAD_SIGNATURE,
        /** 已过期（含正好压在 exp 那一刻）。 */
        EXPIRED,
        /** nbf 还没到。 */
        NOT_YET_VALID,
        /** sub / tenant / exp 缺项，或 exp/iss 类型不对。 */
        MISSING_CLAIM,
        /** 声明值不合规（身份值白名单不过、数字超出范围等）。 */
        CLAIM_INVALID,
        /** 配置了签发方但 iss 对不上。 */
        ISSUER_MISMATCH
    }

    /**
     * 校验结果：成功带身份与令牌自身的过期时刻，失败带原因（两者恰有一个非空）。
     *
     * @param expEpochSeconds 成功时令牌的 {@code exp}（epoch 秒）：这条「通过」结论本身
     *                        也只活到这一刻——结论缓存拿它当复用的硬上限
     *                        （见 IdentityCheckCache），绝不允许越过；失败时无意义，置 0
     */
    public record Result(UserIdentity identity, Failure failure, long expEpochSeconds) {

        public boolean ok() {
            return identity != null;
        }

        static Result ok(UserIdentity identity, long expEpochSeconds) {
            return new Result(identity, null, expEpochSeconds);
        }

        static Result fail(Failure failure) {
            return new Result(null, failure, 0L);
        }
    }

    public Result verify(String token) {
        if (token == null || token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
            return Result.fail(Failure.MALFORMED);
        }

        // 1. 必须恰好三段（-1 保留末尾空段，避免 "xxx." 被错切）
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank()
                || parts[2].isBlank()) {
            return Result.fail(Failure.MALFORMED);
        }
        String signedContent = parts[0] + "." + parts[1];

        // 2. header：先认算法，再谈别的。alg 不是精确的 HS256 直接拒（none、改大小写都不行）
        JsonNode header = decodeJson(parts[0]);
        if (header == null || !header.isObject()) {
            return Result.fail(Failure.MALFORMED);
        }
        JsonNode algNode = header.get("alg");
        if (algNode == null || !algNode.isTextual() || !ALGORITHM.equals(algNode.asText())) {
            return Result.fail(Failure.ALG_REJECTED);
        }

        // 3. 签名：对原始编码段重算 HMAC-SHA256，常量时间比对。光解字段不验签等于没验
        byte[] signature = b64UrlDecode(parts[2]);
        if (signature == null || signature.length == 0) {
            return Result.fail(Failure.MALFORMED);
        }
        byte[] expected = hmacSha256(signedContent);
        if (expected == null || !MessageDigest.isEqual(expected, signature)) {
            return Result.fail(Failure.BAD_SIGNATURE);
        }

        // 4. payload：签名过了才解析内容
        JsonNode payload = decodeJson(parts[1]);
        if (payload == null || !payload.isObject()) {
            return Result.fail(Failure.MALFORMED);
        }

        // exp 必须存在、是能放进 long 的整数秒（写 "never" 是字符串、写超大整数放不进 long，都拒）
        JsonNode expNode = payload.get("exp");
        if (expNode == null) {
            return Result.fail(Failure.MISSING_CLAIM);
        }
        if (!expNode.isIntegralNumber() || !expNode.canConvertToLong()) {
            return Result.fail(Failure.CLAIM_INVALID);
        }
        long exp = expNode.longValue();

        // sub / tenant：非空白文本 + 白名单（要写进上游头，值必须安全）
        String userId = nonBlankText(payload.get("sub"));
        String tenantId = nonBlankText(payload.get(CLAIM_TENANT));
        if (userId == null || tenantId == null) {
            return Result.fail(Failure.MISSING_CLAIM);
        }
        if (!UserIdentity.isValidClaimValue(userId) || !UserIdentity.isValidClaimValue(tenantId)) {
            return Result.fail(Failure.CLAIM_INVALID);
        }

        // 配置了签发方就必须对上
        if (expectedIssuer != null) {
            String issuer = nonBlankText(payload.get("iss"));
            if (!expectedIssuer.equals(issuer)) {
                return Result.fail(Failure.ISSUER_MISMATCH);
            }
        }

        // nbf 存在就认：必须是整数秒，且当前时刻已经到点
        JsonNode nbfNode = payload.get("nbf");
        if (nbfNode != null) {
            if (!nbfNode.isIntegralNumber() || !nbfNode.canConvertToLong()) {
                return Result.fail(Failure.CLAIM_INVALID);
            }
            if (clock.instant().getEpochSecond() < nbfNode.longValue()) {
                return Result.fail(Failure.NOT_YET_VALID);
            }
        }

        // 过期边界卡准：now >= exp 即过期，正好等于的也按过期处理；零宽限
        if (clock.instant().getEpochSecond() >= exp) {
            return Result.fail(Failure.EXPIRED);
        }

        return Result.ok(new UserIdentity(userId, tenantId), exp);
    }

    private JsonNode decodeJson(String b64url) {
        byte[] bytes = b64UrlDecode(b64url);
        if (bytes == null) {
            return null;
        }
        try {
            return objectMapper.readTree(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] b64UrlDecode(String raw) {
        try {
            return Base64.getUrlDecoder().decode(raw);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private byte[] hmacSha256(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            // 算法/密钥固定，正常走不到；走到就当验签失败，绝不抛给调用方
            return null;
        }
    }

    private static String nonBlankText(JsonNode node) {
        if (node == null || !node.isTextual()) {
            return null;
        }
        String v = node.asText().trim();
        return v.isEmpty() ? null : v;
    }
}
