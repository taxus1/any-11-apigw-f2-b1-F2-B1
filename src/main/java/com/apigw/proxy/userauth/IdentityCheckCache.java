package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.UserTokenVerifier;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 验签结论的短缓存：同一枚令牌短时间内反复到达时，省掉重复的 HMAC 计算与 JSON 解析。
 *
 * <p>命中窗口由构造时定死；窗口内一律复用上一次的结论（成功与失败都复用），
 * 窗口一到就把令牌重新交给验签器判。key 取令牌串本身——只有同一枚令牌才谈得上复用。
 *
 * <p>要点：这是纯性能手段，判定口径仍以验签器为准；命中窗口刻意取得比一次转发短得多，
 * 免得结论放太久。
 */
public class IdentityCheckCache {

    private record Entry(UserTokenVerifier.Result result, long cachedAtMillis) {
    }

    private final long windowMillis;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /**
     * @param windowMillis 命中窗口（毫秒）；小于等于 0 表示每次都真验
     */
    public IdentityCheckCache(long windowMillis) {
        this.windowMillis = Math.max(0, windowMillis);
    }

    /** 缓存里现在留着多少条结论（排查用）。 */
    public int size() {
        return entries.size();
    }

    /**
     * 取结论：窗口内的同一枚令牌直接复用，否则交给 {@code verifier} 真验一遍再存下来。
     */
    public UserTokenVerifier.Result check(String token,
                                          Function<String, UserTokenVerifier.Result> verifier) {
        long now = System.currentTimeMillis();
        if (windowMillis > 0) {
            Entry hit = entries.get(token);
            if (hit != null && now - hit.cachedAtMillis() < windowMillis) {
                return hit.result();
            }
        }
        UserTokenVerifier.Result fresh = verifier.apply(token);
        entries.put(token, new Entry(fresh, now));
        return fresh;
    }
}
