package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.UserTokenVerifier;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * 验签结论的短缓存：同一枚令牌短时间内反复到达时，省掉重复的 HMAC 计算与 JSON 解析。
 * 这是纯性能手段，判定口径与验签器严格一致，复用纪律如下：
 *
 * <p>1. <b>复用绝不越过令牌自己的 {@code exp}</b>：「通过」结论的复用上限取
 * 「命中窗口」与「令牌过期时刻」的较小者。窗口可以图省事，但 {@code exp} 一到，
 * 结论立即作废、重新交给验签器判——缓存里不存在「过期后还能用一小会儿」的缝，
 * 与验签器「{@code now >= exp} 即过期、压点也算」的口径逐毫秒对齐。
 *
 * <p>2. <b>失败结论只留「确定型」的</b>（畸形/算法不对/签名错/缺声明/声明不合规/
 * 签发方不符/已过期）：这些结论不随时间翻转，窗口内复用安全。
 * 唯独 {@code nbf} 还没到（NOT_YET_VALID）的结论<b>不留</b>——它到点就该翻转成通过，
 * 存下来会把一张已到生效时刻的令牌继续拒之门外（另一种「说法对不上」）。
 *
 * <p>3. <b>结论只对验它时用的那把密钥有效</b>：缓存与验签器同属一个守门人实例、
 * 同生同灭；密钥轮换或停用即整体重建，旧结论随旧实例一并作废，不跨密钥复用。
 *
 * <p>4. <b>时钟与验签器同一面</b>（构造注入）：缓存量「现在」的钟和验签器判
 * {@code exp}/{@code nbf} 的钟必须是一面，否则窗口与有效期各说各话。
 *
 * <p>key 取令牌串本身——只有同一枚令牌才谈得上复用。条目数有硬上限，
 * 免得被海量一次性令牌把内存撑爆；到顶先清已作废的，清完还满就这次不存（照验不误）。
 */
public class IdentityCheckCache {

    /** 缓存条数硬上限：防海量一次性令牌把 Map 撑爆（只是缓存，存不下不影响判定）。 */
    private static final int MAX_ENTRIES = 10_000;

    /** 一条结论 + 它能复用到哪一刻（epoch 毫秒，窗口与令牌有效期的较小者）。 */
    private record Entry(UserTokenVerifier.Result result, long reusableUntilMillis) {
    }

    private final long windowMillis;
    private final Clock clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /**
     * @param windowMillis 命中窗口（毫秒）；小于等于 0 表示每次都真验
     * @param clock        量「现在」的时钟——必须与验签器判 {@code exp}/{@code nbf} 的同一面
     */
    public IdentityCheckCache(long windowMillis, Clock clock) {
        this.windowMillis = Math.max(0, windowMillis);
        this.clock = clock;
    }

    /** 缓存里现在留着多少条结论（排查用）。 */
    public int size() {
        return entries.size();
    }

    /**
     * 取结论：复用期内的同一枚令牌直接复用，否则交给 {@code verifier} 真验一遍；
     * 验出来的结论按类头纪律决定留不留、留多久。
     */
    public UserTokenVerifier.Result check(String token,
                                          Function<String, UserTokenVerifier.Result> verifier) {
        if (windowMillis <= 0) {
            return verifier.apply(token);
        }
        long now = clock.millis();
        Entry hit = entries.get(token);
        if (hit != null && now < hit.reusableUntilMillis()) {
            return hit.result();
        }
        UserTokenVerifier.Result fresh = verifier.apply(token);
        long reusableUntil = reusableUntil(fresh, now);
        if (reusableUntil > now) {
            put(token, new Entry(fresh, reusableUntil));
        }
        return fresh;
    }

    /**
     * 这条结论能复用到哪一刻（epoch 毫秒；返回值不大于 now 表示不留）：
     * 通过 → 窗口与令牌 {@code exp} 的较小者；确定型失败 → 窗口内；
     * NOT_YET_VALID → 不留（nbf 一到就该翻转，不能被旧结论多挡一阵）。
     */
    private long reusableUntil(UserTokenVerifier.Result result, long now) {
        if (result.ok()) {
            // 饱和换算：exp 极大（接近 Long.MAX_VALUE 秒）时乘 1000 也不会溢出成负数
            long expMillis = TimeUnit.SECONDS.toMillis(result.expEpochSeconds());
            return Math.min(now + windowMillis, expMillis);
        }
        if (result.failure() == UserTokenVerifier.Failure.NOT_YET_VALID) {
            return now;
        }
        return now + windowMillis;
    }

    private void put(String token, Entry entry) {
        if (entries.size() >= MAX_ENTRIES) {
            // 先清已作废的；清完还满就这次不存——缓存只是省验签，不存照验
            entries.values().removeIf(e -> clock.millis() >= e.reusableUntilMillis());
            if (entries.size() >= MAX_ENTRIES) {
                return;
            }
        }
        entries.put(token, entry);
    }
}
