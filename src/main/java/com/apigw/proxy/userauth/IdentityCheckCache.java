package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.UserTokenVerifier;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 验签结论的短缓存：同一枚令牌短时间内反复到达时，省掉重复的 HMAC 计算与 JSON 解析。
 *
 * <p><b>纯性能手段，绝不改变判定口径。</b>三条硬规矩：
 *
 * <ol>
 * <li><b>复用寿命跟着令牌自己的有效期走，不越过过期那一刻。</b>
 *     每条成功结论的复用截止取「缓存时刻 + 窗口」与「令牌 {@code exp}」中较早者；
 *     命中时再按与验签器<b>同一只时钟</b>（同一秒口径）卡一遍 {@code now < exp}。
 *     因此复用窗口恰好在 exp 之前被截断，过期之后第一笔请求必然重新真验，
 *     不存在「过期后还被认一段时间」的缝（{@code now >= exp} 即过期，压点也算）。</li>
 * <li><b>只缓存成功结论，失败一律不留。</b>时间类失败（{@code nbf} 未到、已过期）
 *     本身会随时钟翻盘，任何复用都必须在翻盘点立即失效，留它既复杂又危险；
 *     其他失败（坏签名、缺声明）没有可安全复用的时间上界。坏令牌也不是性能热点，
 *     每笔真验的代价可接受——结论：失败不复用，下一笔请求重新交验签器判。</li>
 * <li><b>时钟只有一只。</b>缓存不自己摸系统时间，用构造时传入的 {@link Clock}，
 *     生产环境与 {@link UserTokenVerifier} 同为 {@code Clock.systemUTC()}，
 *     避免「缓存按 A 钟算窗口、验签按 B 钟算过期」两边说法对不上。</li>
 * </ol>
 *
 * <p>key 取令牌串本身——只有同一枚令牌（同 exp）才谈得上复用。
 * 受保护路由与开放路由<b>共用同一个实例</b>（见 {@link UserAuthGatekeeper}）：
 * 两个入口对同一枚令牌在同一时刻必然给同一个结论，区别只在「失败时拦不拦」
 * （开放路由按匿名放行），判定本身不分叉。
 *
 * <p>缓存是进程内状态、与装配进来的验签器（含其密钥版本）同生命周期。
 * 密钥轮换/停用、验签器被换掉后，旧结论必须用 {@link #invalidate()} 清掉，
 * 绝不能让旧密钥下的成功结论在新密钥下继续命中。
 */
public class IdentityCheckCache {

    private record Entry(UserTokenVerifier.Result result, long cachedAtMillis, long expiryEpochSecond) {
    }

    private final long windowMillis;
    private final Clock clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /**
     * @param windowMillis 命中窗口（毫秒）；小于等于 0 表示每次都真验（结论完全不落缓存）
     * @param clock        与验签器共用的时钟（生产 systemUTC，测试可固定/拨动）
     */
    public IdentityCheckCache(long windowMillis, Clock clock) {
        this.windowMillis = Math.max(0, windowMillis);
        this.clock = clock;
    }

    /** 缓存里现在留着多少条成功结论（排查用）。 */
    public int size() {
        return entries.size();
    }

    /**
     * 取结论：窗口内、且尚未到令牌 {@code exp} 的同一枚令牌直接复用上次的成功结论；
     * 其余情况（窗口过了、正好/已经过期、上次是失败、第一次见）都交给 {@code verifier} 真验。
     * 真验失败时不落任何缓存。
     */
    public UserTokenVerifier.Result check(String token,
                                          Function<String, UserTokenVerifier.Result> verifier) {
        long nowMillis = clock.millis();
        long nowSeconds = clock.instant().getEpochSecond();
        if (windowMillis > 0) {
            Entry hit = entries.get(token);
            if (hit != null
                    && nowMillis - hit.cachedAtMillis() < windowMillis
                    // 与验签器同一秒口径再卡一遍：now >= exp 立刻判失效，压点也不放
                    && nowSeconds < hit.expiryEpochSecond()) {
                return hit.result();
            }
            if (hit != null) {
                // 已到复用终点（窗口滑过或令牌过期）：删掉，逼下面真验并覆盖
                entries.remove(token, hit);
            }
        }
        UserTokenVerifier.Result fresh = verifier.apply(token);
        // 只缓存成功结论；成功一定带着合法的 exp（失败不带，也不缓存）
        if (windowMillis > 0 && fresh.ok() && fresh.expiryEpochSecond() != null) {
            entries.put(token, new Entry(fresh, nowMillis, fresh.expiryEpochSecond()));
        }
        return fresh;
    }

    /**
     * 清空全部已缓存结论。密钥轮换/停用、验签器换密钥版本后必须调用：
     * 旧密钥下的成功结论在新密钥下一条都不能再复用。
     */
    public void invalidate() {
        entries.clear();
    }
}
