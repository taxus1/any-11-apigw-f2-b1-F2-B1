package com.apigw.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 测试用时钟：从固定起点出发，可向前拨动（毫秒/秒），验签器与结论缓存拿同一只钟，
 * 用来构造「验过之后令牌才到期」「复用窗口跨过过期点」「nbf 还没到/刚到」这类时序场景。
 */
public final class MutableClock extends Clock {

    private Instant instant;
    private final ZoneId zone;

    public MutableClock(Instant start) {
        this(start, ZoneOffset.UTC);
    }

    public MutableClock(Instant start, ZoneId zone) {
        this.instant = start;
        this.zone = zone;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new MutableClock(instant, zone);
    }

    @Override
    public Instant instant() {
        return instant;
    }

    /** 向前拨（仅支持向前：时间不倒退，模拟真实时钟单调前进）。 */
    public void advance(Duration duration) {
        if (duration.isNegative()) {
            throw new IllegalArgumentException("测试时钟只向前拨");
        }
        instant = instant.plus(duration);
    }

    public void advanceSeconds(long seconds) {
        advance(Duration.ofSeconds(seconds));
    }

    public void advanceMillis(long millis) {
        advance(Duration.ofMillis(millis));
    }
}
