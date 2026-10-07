package com.apigw.support;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 可拨动的测试时钟：验签器与结论缓存共用同一面，测试里随拨随走，
 * 用来精确复现「复用窗口跨过过期点」「nbf 到点翻转」这类跟时间赛跑的场面。
 */
public final class MutableClock extends Clock {

    private final AtomicLong epochMillis;

    private MutableClock(long epochMillis) {
        this.epochMillis = new AtomicLong(epochMillis);
    }

    public static MutableClock at(Instant start) {
        return new MutableClock(start.toEpochMilli());
    }

    public void advanceSeconds(long seconds) {
        epochMillis.addAndGet(seconds * 1_000L);
    }

    public void advanceMillis(long millis) {
        epochMillis.addAndGet(millis);
    }

    @Override
    public Instant instant() {
        return Instant.ofEpochMilli(epochMillis.get());
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }
}
