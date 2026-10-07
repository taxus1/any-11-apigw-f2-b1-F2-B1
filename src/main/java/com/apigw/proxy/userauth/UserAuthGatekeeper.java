package com.apigw.proxy.userauth;

import com.apigw.common.web.GatewayHeaders;
import com.apigw.domain.userauth.GatewayPassSigner;
import com.apigw.domain.userauth.UserIdentity;
import com.apigw.domain.userauth.UserTokenVerifier;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.time.Clock;

/**
 * 用户登录鉴权的守门人：转发过滤器在匹配到路由之后，拿它做两件事——
 *
 * 1. <b>验令牌</b>：从 {@code Authorization: Bearer <token>} 取令牌，交给
 *    {@link UserTokenVerifier} 真验签。受保护路由（authRequired=1）验不过就 401；
 *    开放路由上令牌只是「可选的身份补充」——带对了照常透传身份，没带/带错按匿名放行，
 *    绝不拦（统一口径，理由见 README「开放路由上的坏令牌」）。
 *
 * 2. <b>组装出站身份</b>：验出的身份 + 网关自盖的通行标记，打包成 {@link OutboundAuth}
 *    交给转发器写向上游。身份头只可能来自这里，调用方在入站塞的同名头转发器会先清掉。
 *
 * 验签结论的短缓存只有<b>一套</b>（见 {@link IdentityCheckCache}）：受保护路由与开放路由
 * 共用同一实例、同一窗口、同一只时钟，所以同一枚令牌在同一时刻两个入口的判定必然一致；
 * 复用寿命被令牌自身的 {@code exp} 截断，且只缓存成功结论。两个入口的区别只剩
 * 「验不过时拦不拦」——受保护路由 401，开放路由按匿名放行。
 *
 * 两个协作者都可为空（取决于 {@code apigw.user-auth.*} 是否配了密钥）：
 * 没配验签密钥时受保护路由 fail-closed（由过滤器判 503），开放路由不受影响。
 */
public class UserAuthGatekeeper {

    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * 验签结论的复用窗口：只是省重复 HMAC 的性能上限，实际复用寿命取它与令牌
     * {@code exp} 的较早者，绝不会越过过期时刻。两个入口共用这一个值，不允许分叉。
     */
    private static final long CHECK_WINDOW_MILLIS = 60_000L;

    private final UserTokenVerifier verifier;
    private final GatewayPassSigner passSigner;
    private final IdentityCheckCache checks;

    /** 生产装配用：按固定窗口与给定时钟（与验签器同一只 UTC 钟）建共享缓存。 */
    public UserAuthGatekeeper(UserTokenVerifier verifier, GatewayPassSigner passSigner, Clock clock) {
        this(verifier, passSigner, new IdentityCheckCache(CHECK_WINDOW_MILLIS, clock));
    }

    /** 测试/定制装配用：缓存实例可从外部给定（例如固定窗口为 0 或可拨时钟）。 */
    public UserAuthGatekeeper(UserTokenVerifier verifier, GatewayPassSigner passSigner,
                              IdentityCheckCache checks) {
        this.verifier = verifier;
        this.passSigner = passSigner;
        this.checks = checks;
    }

    /** 是否配了验签密钥（没配时受保护路由必须 fail-closed，不能裸放行）。 */
    public boolean tokenVerificationEnabled() {
        return verifier != null;
    }

    /**
     * 从请求里取 Bearer 令牌：scheme 大小写不敏感（RFC 7235），
     * 没带、不是 Bearer、令牌段空白都返回 null（调用方按「没带令牌」处理）。
     */
    public String extractBearerToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(GatewayHeaders.AUTHORIZATION_HEADER);
        if (header == null) {
            return null;
        }
        String v = header.trim();
        if (v.length() <= BEARER_PREFIX.length()
                || !v.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return null;
        }
        String token = v.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    /** 真验签：签名、过期、nbf、必备声明逐项过（见 {@link UserTokenVerifier}）。 */
    public UserTokenVerifier.Result verify(String token) {
        return checks.check(token, verifier::verify);
    }

    /**
     * 开放路由专用：带了令牌就试着验，验过给身份；没带或验不过一律当匿名（返回 null），
     * 开放路由绝不因为令牌问题拦人。判定本身与受保护路由走同一个缓存、同一口径，
     * 只是处理结论的方式不同。
     */
    public UserIdentity tryVerifyIdentity(ServerHttpRequest request) {
        if (verifier == null) {
            return null;
        }
        String token = extractBearerToken(request);
        if (token == null) {
            return null;
        }
        UserTokenVerifier.Result result = checks.check(token, verifier::verify);
        return result.ok() ? result.identity() : null;
    }

    /**
     * 组装发往上游的身份上下文。通行标记把 traceId/方法/路径/身份和时间戳一起签进去，
     * 上游用共享密钥验得出「确实过了网关、且身份头没被换过」。
     */
    public OutboundAuth outbound(String traceId, ServerHttpRequest request, UserIdentity identity) {
        String pass = null;
        if (passSigner != null) {
            String method = request.getMethod() == null ? "" : request.getMethod().name();
            String path = request.getPath().pathWithinApplication().value();
            pass = passSigner.sign(System.currentTimeMillis(), traceId, method, path,
                    identity == null ? "" : identity.userId(),
                    identity == null ? "" : identity.tenantId());
        }
        // 用户鉴权启用时，原始令牌（Authorization）不递上游
        return new OutboundAuth(identity, pass, verifier != null);
    }
}
