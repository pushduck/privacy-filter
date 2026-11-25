package filter

import (
	"strings"
	"testing"
)

// 拼接构造测试串，避免样本本身被上游脱敏工具改写。
func j(parts ...string) string { return strings.Join(parts, "") }

// w 展开期望值里的占位符记号（S=密钥 H=服务器 D=域名 U=用户名 B=订阅链接 N=节点 R=订阅内容 I=IP）。
var w = strings.NewReplacer("{S}", labelSecret, "{H}", labelServer, "{D}", labelHost, "{U}", labelUser,
	"{B}", labelSub, "{N}", labelNode, "{R}", labelSubRaw, "{I}", "[IP]").Replace

func TestShareLinks(t *testing.T) {
	f := newFilter(t)
	cases := []struct{ in, want string }{
		{
			j("vless://", "b831381d-6324-4d53-ad4f-8cda48b30811", "@", "203.0.113.7", ":443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=", "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#香港01"),
			"vless://{S}@{H}:443?encryption=none&security=reality&sni={D}&fp=chrome&pbk={S}&sid={S}&type=tcp&flow=xtls-rprx-vision#香港01",
		},
		{
			j("trojan://", "pa", "ss", "@", "node.example.com", ":443?sni=node.example.com#t1"),
			"trojan://{S}@{H}:443?sni={D}#t1",
		},
		{
			j("ss://", "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz", "@", "198.51.100.2", ":8388#node"),
			"ss://{S}@{H}:8388#node",
		},
		{
			j("hysteria2://", "letmein", "@[2001:db8::1]:443,20000-30000/?obfs=salamander&obfs-password=", "gawrgura", "&sni=bing.com#hy"),
			"hysteria2://{S}@{H}:443,20000-30000/?obfs=salamander&obfs-password={S}&sni={D}#hy",
		},
		{
			j("vmess://", "eyJ2IjoiMiIsInBzIjoiaGsiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiYWJjIn0="),
			"vmess://{N}",
		},
		{
			// 本机代理地址不脱
			j("export all_proxy=socks5://", "127", ".0.0.1", ":7890"),
			"export all_proxy=socks5://{I}:7890",
		},
		{
			j("节点：tuic://", "uuid-x:pw-y", "@", "tuic.example.org", ":443?congestion_control=bbr。"),
			"节点：tuic://{S}@{H}:443?congestion_control=bbr。",
		},
	}
	for _, c := range cases {
		if got := f.Redact(c.in).Redacted; got != w(c.want) {
			t.Errorf("\n  in  : %q\n  got : %q\n  want: %q", c.in, got, w(c.want))
		}
	}
}

func TestSubscriptionURL(t *testing.T) {
	f := newFilter(t)
	cases := []struct{ in, want string }{
		{j("订阅：https://sub.example.com/api/v1/client/subscribe?token=", "abcdef0123456789", "，用这个"), "订阅：{B}，用这个"},
		{j("https://example.com/link/", "Xy12Ab34", "?clash=1"), "{B}"},
		{j("https://api.example.net/sub?target=clash&url=", "x"), "{B}"},
		// 普通链接不动
		{"文档见 https://wiki.metacubex.one/config/proxies/", "文档见 https://wiki.metacubex.one/config/proxies/"},
		{"https://cp.cloudflare.com/generate_204", "https://cp.cloudflare.com/generate_204"},
	}
	for _, c := range cases {
		if got := f.Redact(c.in).Redacted; got != w(c.want) {
			t.Errorf("\n  in  : %q\n  got : %q\n  want: %q", c.in, got, w(c.want))
		}
	}
}

func TestBase64Subscription(t *testing.T) {
	f := newFilter(t)
	// base64("trojan://p@h.example.com:443#a\nss://x@h2.example.com:1#b\n")
	in := "dHJvamFuOi8vcEBoLmV4YW1wbGUuY29tOjQ0MyNhCnNzOi8veEBoMi5leGFtcGxlLmNvbToxI2IK"
	if got := f.Redact(in).Redacted; got != w("{R}") {
		t.Errorf("base64 订阅内容未脱敏: %q", got)
	}
}

func TestMihomoYAML(t *testing.T) {
	f := newFilter(t)
	in := j(`mixed-port: 7890
secret: "`, "s3cr3t-api", `"
authentication:
  - "`, "admin:hunter2", `"
proxies:
  - name: "香港 01"
    type: vless
    server: hk.example.net
    port: 443
    uuid: `, "b831381d-6324-4d53-ad4f-8cda48b30811", `
    servername: www.microsoft.com # REALITY
    reality-opts:
      public-key: `, "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", `
      short-id: 6ba85179
    ws-opts:
      headers:
        Host: cdn.example.net
  - {name: ss1, type: ss, server: 203.0.113.9, port: 8388, cipher: aes-256-gcm, password: "`, "p@ss,word", `", udp: true}
  - name: wg
    type: wireguard
    server: 198.51.100.4
    private-key: `, "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=", `
    # pre-shared-key: `, "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=", `
    peers:
      - server: 198.51.100.5
        public-key: `, "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=", `
  - name: ovpn
    type: openvpn
    server: vpn.example.com
    auth: SHA256
    key: |
      -----BEGIN PRIVATE KEY-----
      `, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", `
      -----END PRIVATE KEY-----
    udp: true
  - name: h2
    type: vmess
    server: v.example.com
    uuid: `, "11111111-2222-3333-4444-555555555555", `
    h2-opts:
      host:
        - http.example.com
      path: /
proxy-providers:
  airport:
    type: http
    url: "`, "https://panel.example.com/s/abc?x=1", `"
    interval: 3600
    health-check:
      enable: true
      url: https://cp.cloudflare.com/generate_204
listeners:
  - name: tuic-in
    type: tuic
    port: 10443
    users:
      `, "00000000-0000-0000-0000-000000000000: PASSWORD_0", `
  - name: vmess-in
    type: vmess
    users:
      - username: 1
        uuid: `, "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", `
        alterId: 1
`)
	want := w(`mixed-port: 7890
secret: "{S}"
authentication:
  - "{S}"
proxies:
  - name: "香港 01"
    type: vless
    server: {H}
    port: 443
    uuid: {S}
    servername: {D} # REALITY
    reality-opts:
      public-key: {S}
      short-id: {S}
    ws-opts:
      headers:
        Host: {D}
  - {name: ss1, type: ss, server: {H}, port: 8388, cipher: aes-256-gcm, password: "{S}", udp: true}
  - name: wg
    type: wireguard
    server: {H}
    private-key: {S}
    # pre-shared-key: {S}
    peers:
      - server: {H}
        public-key: {S}
  - name: ovpn
    type: openvpn
    server: {H}
    auth: SHA256
    key: |
      {S}
    udp: true
  - name: h2
    type: vmess
    server: {H}
    uuid: {S}
    h2-opts:
      host:
        - {D}
      path: /
proxy-providers:
  airport:
    type: http
    url: "{B}"
    interval: 3600
    health-check:
      enable: true
      url: https://cp.cloudflare.com/generate_204
listeners:
  - name: tuic-in
    type: tuic
    port: 10443
    users:
      {U}: {S}
  - name: vmess-in
    type: vmess
    users:
      - username: {U}
        uuid: {S}
        alterId: 1
`)
	got := f.Redact(in).Redacted
	if got != want {
		gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Errorf("第 %d 行\n  got : %q\n  want: %q", i+1, g, w)
			}
		}
	}
}

func TestProxyJSON(t *testing.T) {
	f := newFilter(t)
	in := j(`{"outbounds":[{"type":"vless","server":"203.0.113.1","server_port":443,"uuid":"`, "b831381d-6324-4d53-ad4f-8cda48b30811",
		`","tls":{"server_name":"a.example.com","reality":{"public_key":"`, "abcDEF123xyz", `"}}}]}`)
	want := w(`{"outbounds":[{"type":"vless","server":"{H}","server_port":443,"uuid":"{S}","tls":{"server_name":"{D}","reality":{"public_key":"{S}"}}}]}`)
	if got := f.Redact(in).Redacted; got != want {
		t.Errorf("\n  got : %q\n  want: %q", got, want)
	}
}

// 非代理配置里的 server / host / key 字段不应被当成节点信息。
func TestProxyFieldsNeedContext(t *testing.T) {
	f := newFilter(t)
	for _, in := range []string{
		"server:\n  host: db.internal\n  port: 5432\n",
		"spec:\n  selector:\n    key: app\n    host: web.example.com\n",
		"type: http\nserver: api.example.com\n",
	} {
		if got := f.Redact(in).Redacted; got != in {
			t.Errorf("无代理上下文却被改写:\n  in : %q\n  got: %q", in, got)
		}
	}
}
