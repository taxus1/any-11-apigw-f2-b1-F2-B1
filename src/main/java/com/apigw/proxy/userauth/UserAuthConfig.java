package com.apigw.proxy.userauth;

import com.apigw.domain.userauth.GatewayPassSigner;
import com.apigw.domain.userauth.UserTokenVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 用户登录令牌鉴权的装配。<b>始终装配</b>：即使没配密钥也装一个「空」守门人，
 * 这样开放路由与受保护路由走同一条链路（零配置本地环境照常跑）；
 * 真遇到配了「需登录」却没配密钥的情况，由转发过滤器 fail-closed 回 503。
 *
 * 密钥只从 {@link UserAuthProperties}（环境变量/外部配置）来，代码里不内置任何默认密钥。
 */
@Slf4j
@Configuration
@EnableConfigurationProperties(UserAuthProperties.class)
public class UserAuthConfig {

    /** HMAC 密钥建议长度（低于它只告警不拦，真正的安全靠部署把密钥配够长）。 */
    private static final int RECOMMENDED_SECRET_LENGTH = 32;

    @Bean
    UserAuthGatekeeper userAuthGatekeeper(UserAuthProperties properties, ObjectMapper objectMapper) {
        // 验签器判 exp/nbf 与结论缓存算复用窗口必须用同一只钟，这里造一只两者共用；
        // 与 app-auth 侧的 gatewayClock 同为 systemUTC（未声明成 Bean，避免按类型注入 Clock 的歧义）
        Clock clock = Clock.systemUTC();
        UserTokenVerifier verifier = null;
        if (properties.tokenVerificationEnabled()) {
            if (properties.tokenSecret().length() < RECOMMENDED_SECRET_LENGTH) {
                log.warn("用户令牌验签密钥长度低于建议的 {} 字符，生产请配足够长的随机密钥",
                        RECOMMENDED_SECRET_LENGTH);
            }
            verifier = new UserTokenVerifier(properties.tokenSecret(), properties.issuer(),
                    clock, objectMapper);
        } else {
            log.info("未配置 apigw.user-auth.token-secret：用户令牌鉴权未启用，"
                    + "开放路由照常转发，配了「需登录」的路由将 fail-closed 回 503");
        }

        GatewayPassSigner signer = null;
        if (properties.passSigningEnabled()) {
            signer = new GatewayPassSigner(properties.effectivePassSecret());
        }
        // verifier 可能为 null（未配密钥），时钟照样传入：缓存本就只在 verifier 存在时被用到
        return new UserAuthGatekeeper(verifier, signer, clock);
    }
}
