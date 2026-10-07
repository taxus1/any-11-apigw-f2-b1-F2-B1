package com.apigw.proxy;

import com.apigw.domain.route.GatewayRoute;
import com.apigw.domain.route.GatewayRule;
import com.apigw.proxy.accesslog.AccessLogRecorder;
import com.apigw.proxy.config.GatewayProxyProperties;
import com.apigw.proxy.cors.GatewayCorsProperties;
import com.apigw.proxy.cors.GatewayCorsWebFilter;
import com.apigw.proxy.match.RouteMatcher;
import com.apigw.proxy.route.RouteCatalog;
import com.apigw.proxy.userauth.UserAuthGatekeeper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.HttpWebHandlerAdapter;
import org.springframework.web.server.handler.FilteringWebHandler;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 跨域过滤器端到端（真实 Netty）：
 * - 预检请求由网关直接回 200（带 ACAO / Allow-Headers / Allow-Methods），不进鉴权、不匹配路由；
 * - 实际响应（含网关自己的 401）一律带 ACAO 与 Access-Control-Expose-Headers，
 *   身份头/追踪号/错误标识前端跨域读得到；
 * - 非通配名单下，不在名单的来源拿不到 CORS 头。
 */
class GatewayCorsWebFilterTest {

    private FakeUpstream upstream;
    private InMemoryRouteStore store;
    private RouteCatalog catalog;
    private DisposableServer server;
    private String baseUrl;
    private WebClient client;

    @BeforeEach
    void setUp() throws Exception {
        upstream = new FakeUpstream();
        store = new InMemoryRouteStore();
        var props = new GatewayProxyProperties(
                Duration.ofMillis(500), Duration.ofMillis(800), Duration.ofHours(1));
        catalog = new RouteCatalog(store, props);
        loadRoutes();

        var corsProps = new GatewayCorsProperties(true, List.of("*"), null, List.of("*"), null, Duration.ofHours(1));
        server = startServer(corsProps);
        baseUrl = "http://127.0.0.1:" + server.port();
        client = WebClient.builder().build();
    }

    private DisposableServer startServer(GatewayCorsProperties corsProps) {
        var nettyClient = reactor.netty.http.client.HttpClient.create();
        var webClient = WebClient.builder()
                .clientConnector(new org.springframework.http.client.reactive.ReactorClientHttpConnector(nettyClient))
                .build();
        var proxyFilter = new GatewayProxyWebFilter(
                catalog, new RouteMatcher(),
                new com.apigw.proxy.forward.UpstreamForwarder(webClient),
                new AccessLogRecorder(), e -> { }, new ObjectMapper(),
                // 配上验签器，受保护路由缺令牌时才会走 401（而不是配置缺失的 503）
                new UserAuthGatekeeper(
                        new com.apigw.domain.userauth.UserTokenVerifier(
                                "cors-test-token-secret-0123456789abcdef", null,
                                java.time.Clock.systemUTC(), new ObjectMapper()),
                        null, java.time.Clock.systemUTC()));
        var corsFilter = new GatewayCorsWebFilter(corsProps);
        WebHandler tail = exchange -> {
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            return exchange.getResponse().setComplete();
        };
        // CORS 在前（HIGHEST_PRECEDENCE），转发在后
        WebHandler filtering = new FilteringWebHandler(tail, List.of(corsFilter, proxyFilter));
        HttpWebHandlerAdapter adapter = new HttpWebHandlerAdapter(filtering);
        adapter.afterPropertiesSet();
        HttpHandler httpHandler = adapter;
        return HttpServer.create().handle(new ReactorHttpHandlerAdapter(httpHandler)).bindNow();
    }

    private void loadRoutes() {
        GatewayRule cond = GatewayRule.create("REQUEST", "PATH_PREFIX", null, "/open/", 1);
        GatewayRoute open = GatewayRoute.create("open", "open", upstream.baseUrl(), 1, null);
        open.changeAuthRequired(0);
        open.replaceRules(List.of(cond), List.of());
        GatewayRule cond2 = GatewayRule.create("REQUEST", "PATH_PREFIX", null, "/secure/", 1);
        GatewayRoute secure = GatewayRoute.create("secure", "secure", upstream.baseUrl(), 1, null);
        secure.changeAuthRequired(1);
        secure.replaceRules(List.of(cond2), List.of());
        store.setRoutes(List.of(open, secure));
        catalog.refresh().block();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.disposeNow();
        }
        upstream.close();
    }

    @Test
    void preflight_isAnsweredDirectly_withoutAuthOrRouting() {
        var resp = client.options().uri(baseUrl + "/secure/1")
                .header(HttpHeaders.ORIGIN, "https://web.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization,Content-Type,X-Trace-Id")
                .exchange().block();
        assertThat(resp.statusCode()).isEqualTo(HttpStatus.OK);
        HttpHeaders h = resp.headers().asHttpHeaders();
        assertThat(h.getAccessControlAllowOrigin()).isEqualTo("*");
        // 浏览器申请的头原样放行（含令牌头 Authorization）
        assertThat(h.getAccessControlAllowHeaders())
                .anySatisfy(s -> assertThat(s).containsIgnoringCase("Authorization"));
        assertThat(h.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).contains("POST");
        // 预检不打上游
        assertThat(upstream.lastExchange()).isNull();
        resp.releaseBody().block();
    }

    @Test
    void actualRequest_exposesIdentityAndErrorHeaders_evenOn401() {
        // 受保护路由没带令牌 → 401，但 CORS 头照样在，前端跨域读得到错误标识
        var resp = client.get().uri(baseUrl + "/secure/1")
                .header(HttpHeaders.ORIGIN, "https://web.example.com")
                .exchange().block();
        assertThat(resp.statusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        HttpHeaders h = resp.headers().asHttpHeaders();
        assertThat(h.getAccessControlAllowOrigin()).isEqualTo("*");
        String exposed = h.getAccessControlExposeHeaders().stream().reduce("", (a, b) -> a + "," + b);
        assertThat(exposed).contains("X-User-Id").contains("X-Tenant-Id")
                .contains("X-Gateway-Trace-Id").contains("X-Gateway-Error");
        resp.releaseBody().block();
    }

    @Test
    void actualRequest_onSuccessfulForward_carriesCorsHeaders() {
        var resp = client.get().uri(baseUrl + "/open/1")
                .header(HttpHeaders.ORIGIN, "https://web.example.com")
                .exchange().block();
        assertThat(resp.statusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.headers().asHttpHeaders().getAccessControlAllowOrigin()).isEqualTo("*");
        resp.releaseBody().block();
    }

    @Test
    void requestWithoutOrigin_getsNoCorsHeaders() {
        var resp = client.get().uri(baseUrl + "/open/1").exchange().block();
        assertThat(resp.statusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.headers().asHttpHeaders().getAccessControlAllowOrigin()).isNull();
        resp.releaseBody().block();
    }

    @Test
    void originOutsideAllowList_isNotGranted() {
        server.disposeNow();
        var strictProps = new GatewayCorsProperties(true,
                List.of("https://trusted.example.com"), null, List.of("*"), null, Duration.ofHours(1));
        server = startServer(strictProps);
        baseUrl = "http://127.0.0.1:" + server.port();

        var preflight = client.options().uri(baseUrl + "/open/1")
                .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .exchange().block();
        assertThat(preflight.statusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(preflight.headers().asHttpHeaders().getAccessControlAllowOrigin()).isNull();
        preflight.releaseBody().block();

        var actual = client.get().uri(baseUrl + "/open/1")
                .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .exchange().block();
        assertThat(actual.headers().asHttpHeaders().getAccessControlAllowOrigin()).isNull();
        actual.releaseBody().block();

        // 名单内的来源正常放并回显精确来源
        var trusted = client.get().uri(baseUrl + "/open/1")
                .header(HttpHeaders.ORIGIN, "https://trusted.example.com")
                .exchange().block();
        assertThat(trusted.headers().asHttpHeaders().getAccessControlAllowOrigin())
                .isEqualTo("https://trusted.example.com");
        trusted.releaseBody().block();
    }
}
