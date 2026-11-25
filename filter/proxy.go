package filter

import (
	"encoding/base64"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 代理配置层：识别 mihomo / Clash（及 sing-box / Xray JSON）配置、节点分享链接、
// 订阅链接里的服务器地址与凭据。
//
//   - 分享链接（vless:// ss:// …）与订阅链接、base64 订阅内容：任意文本都检测，形态足够特异。
//   - 配置字段（server / password / uuid …）：只有文本被判定为代理配置时才检测，
//     避免把普通 YAML 里的 server/key/host 误当成节点信息。
//
// 不依赖 YAML 库（filter 包只允许依赖 toml），按行做轻量解析：支持块样式、
// 流样式 {k: v}、注释掉的字段、块标量（| >）、块列表，以及 JSON 的 "k": "v"。

const (
	labelServer = "[服务器]"
	labelSecret = "[密钥]"
	labelUser   = "[用户名]"
	labelHost   = "[域名]"
	labelSub    = "[订阅链接]"
	labelNode   = "[节点]"
	labelSubRaw = "[订阅内容]"
)

// 节点分享链接的协议名（小写）。
var shareSchemes = toSet("vless", "vmess", "ssr", "ss", "trojan", "trojan-go", "hysteria2", "hysteria", "hy2",
	"tuic", "anytls", "snell", "socks5h", "socks5", "socks4", "socks", "wireguard", "wg", "juicity", "mieru",
	"shadowquic", "naive+https", "naive+quic")

// 订阅链接：常见机场面板 / 订阅转换的路径与参数特征。
var reSubPattern = regexp.MustCompile(`(?i)(?:/api/v\d+/client/|subscribe|/sub(?:/|\?|$)|/link/|/s/[A-Za-z0-9]{16,}|[?&](?:clash|mu|sub)=|[?&]flag=(?:clash|meta|mihomo|clash-meta|stash|v2ray|shadowrocket)|[?&]target=(?:clash|clashr|mihomo|surge|quanx|v2ray|singbox))`)

func toSet(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

// isURLChar 判断链接主体字符：只取可见 ASCII，遇到空白、引号、尖括号、反引号或中文等即结束。
func isURLChar(c byte) bool {
	return c > ' ' && c < 0x7f && c != '"' && c != '\'' && c != '<' && c != '>' && c != '`'
}

// urlMatch 是一个 scheme://… 命中。
type urlMatch struct {
	start, end int
	scheme     string // 小写
}

// findURLs 以 "://" 为锚点找出所有链接，比整段跑正则快得多。
// #fragment（节点名）允许任意非空白字符（常见中文节点名）。
func findURLs(text string) []urlMatch {
	var out []urlMatch
	from := 0
	for {
		i := strings.Index(text[from:], "://")
		if i < 0 {
			return out
		}
		i += from
		s := i
		for s > 0 && isSchemeChar(text[s-1]) {
			s--
		}
		e := i + 3
		for e < len(text) && isURLChar(text[e]) && text[e] != '#' {
			e++
		}
		if e < len(text) && text[e] == '#' {
			for e < len(text) {
				r, size := utf8.DecodeRuneInString(text[e:])
				if unicode.IsSpace(r) || r == '"' || r == '\'' || r == '<' || r == '>' || r == '`' {
					break
				}
				e += size
			}
		}
		from = i + 3
		if s == i || e == i+3 {
			continue
		}
		out = append(out, urlMatch{s, e, strings.ToLower(text[s:i])})
		if e > from {
			from = e
		}
	}
}

// 判定文本是否为代理配置：出现节点类型或 mihomo 顶层段落。
var (
	reProxyType    = regexp.MustCompile(`(?i)["']?\btype["']?\s*:\s*["']?(?:ss|ssr|shadowsocks|vmess|vless|trojan|hysteria|hysteria2|tuic|wireguard|snell|anytls|mieru|shadowquic|sudoku|masque|trusttunnel|socks5|ssh|openvpn|tailscale|easytier|zerotier|gost-relay|juicity|naive)\b`)
	reProxySection = regexp.MustCompile(`(?m)^(?:proxies|proxy-providers|proxy-groups|listeners|tuic-server)\s*:`)
)

// 字段名（小写、_ 统一为 -）→ 占位符。
var proxyKeyLabels = map[string]string{
	// 服务器地址
	"server": labelServer, "address": labelServer, "server-url": labelServer,
	"ip": "[IP]", "ipv6": "[IP]", "peers": labelServer, "endpoint": labelServer,
	// 用户名
	"username": labelUser, "user": labelUser,
	// SNI / 伪装域名
	"servername": labelHost, "server-name": labelHost, "sni": labelHost, "host": labelHost, "peer": labelHost,
	// 密钥 / 凭据
	"password": labelSecret, "passwd": labelSecret, "uuid": labelSecret, "psk": labelSecret,
	"pre-shared-key": labelSecret, "preshared-key": labelSecret, "presharedkey": labelSecret,
	"private-key": labelSecret, "privatekey": labelSecret, "public-key": labelSecret, "publickey": labelSecret,
	"local-private-key": labelSecret, "local-public-key": labelSecret,
	"short-id": labelSecret, "shortid": labelSecret, "short-ids": labelSecret, "shortids": labelSecret,
	"auth": labelSecret, "auth-str": labelSecret, "auth-key": labelSecret, "obfs-password": labelSecret,
	"token": labelSecret, "key": labelSecret, "secret": labelSecret, "age-secret-key": labelSecret,
	"identity-secret": labelSecret, "network-secret": labelSecret, "header-protection-key": labelSecret,
	"seed": labelSecret, "encryption": labelSecret, "authentication": labelSecret, "ech-key": labelSecret,
	"ca": labelSecret, "cert": labelSecret, "tls-auth": labelSecret, "tls-crypt": labelSecret, "tls-crypt-v2": labelSecret,
	"users": labelSecret, "authorization": labelSecret,
}

// 这些值不是真值（布尔、空值、协议关键字），跳过。
var proxyBenignValues = map[string]bool{
	"": true, "~": true, "null": true, "true": true, "false": true, "none": true, "auto": true,
	"[]": true, "{}": true,
}

func isLocalHost(h string) bool {
	h = strings.Trim(strings.ToLower(h), "[]")
	if h == "localhost" || h == "" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// detectProxy 返回代理配置层的命中区间。
func detectProxy(text string) []span {
	var spans []span
	spans = append(spans, detectLinks(text)...)
	spans = append(spans, detectBase64Subs(text)...)
	if looksLikeProxyConfig(text) {
		spans = append(spans, scanProxyConfig(text)...)
	}
	return spans
}

// looksLikeProxyConfig 先做字面量预筛，再跑正则。
func looksLikeProxyConfig(text string) bool {
	for _, kw := range []string{"proxies", "proxy-providers", "proxy-groups", "listeners", "tuic-server"} {
		if strings.Contains(text, kw) && reProxySection.MatchString(text) {
			return true
		}
	}
	if strings.Contains(text, "type") || strings.Contains(text, "Type") || strings.Contains(text, "TYPE") {
		return reProxyType.MatchString(text)
	}
	return false
}

// ---------- 分享链接 ----------

// 分享链接 query 中需要脱敏的参数。
var shareParamLabels = map[string]string{
	"pbk": labelSecret, "sid": labelSecret, "password": labelSecret, "obfs-password": labelSecret,
	"obfs_password": labelSecret, "obfs-param": labelSecret, "obfsparam": labelSecret, "auth": labelSecret,
	"key": labelSecret, "psk": labelSecret, "publickey": labelSecret, "public-key": labelSecret,
	"privatekey": labelSecret, "private-key": labelSecret, "secret": labelSecret, "uuid": labelSecret,
	"token": labelSecret, "seed": labelSecret, "encryption": labelSecret, "presharedkey": labelSecret,
	"sni": labelHost, "peer": labelHost, "host": labelHost, "servername": labelHost,
	"address": labelServer, "ip": labelServer,
}

func trimLinkTail(s string) string {
	return strings.TrimRight(s, ".,;:!?)]}>，。；：！？、）】」")
}

// detectLinks 处理节点分享链接与订阅链接。
func detectLinks(text string) []span {
	var spans []span
	for _, m := range findURLs(text) {
		link := trimLinkTail(text[m.start:m.end])
		switch {
		case shareSchemes[m.scheme]:
			spans = append(spans, shareLinkSpans(link, m.start)...)
		case (m.scheme == "http" || m.scheme == "https") && reSubPattern.MatchString(link):
			spans = append(spans, span{m.start, m.start + len(link), labelSub})
		}
	}
	return spans
}

// shareLinkSpans 拆解一条分享链接：userinfo → [密钥]、host → [服务器]、敏感参数 → 对应占位符，
// 端口、传输参数与 #节点名 保留。无法结构化拆解的（vmess/ssr base64、旧式 ss）整体替换为 [节点]。
func shareLinkSpans(link string, base int) []span {
	sep := strings.Index(link, "://")
	scheme := strings.ToLower(link[:sep])
	bodyStart := sep + 3
	body := link[bodyStart:]
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i] // #节点名 保留
	}
	if body == "" {
		return nil
	}
	pre := body
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		pre, query = body[:i], body[i+1:]
	}
	at := strings.LastIndexByte(pre, '@')
	if scheme == "vmess" || scheme == "ssr" || at < 0 {
		if at < 0 && scheme != "vmess" && scheme != "ssr" && strings.Contains(pre, ":") && !looksBase64(pre) {
			// 无凭据的 host:port（如 socks5://host:1080）：只脱 host
			return hostSpans(pre, base+bodyStart)
		}
		return []span{{base + bodyStart, base + bodyStart + len(body), labelNode}}
	}
	var spans []span
	if at > 0 {
		spans = append(spans, span{base + bodyStart, base + bodyStart + at, labelSecret})
	}
	spans = append(spans, hostSpans(pre[at+1:], base+bodyStart+at+1)...)
	if query != "" {
		off := base + bodyStart + len(pre) + 1
		for _, kv := range strings.Split(query, "&") {
			k, v, ok := strings.Cut(kv, "=")
			if lbl := shareParamLabels[strings.ToLower(k)]; ok && lbl != "" && v != "" && !proxyBenignValues[strings.ToLower(v)] {
				vs := off + len(k) + 1
				spans = append(spans, span{vs, vs + len(v), lbl})
			}
			off += len(kv) + 1
		}
	}
	return spans
}

// hostSpans 处理 host:port[/path]，返回 host 的区间（本机地址不脱）。
func hostSpans(hp string, base int) []span {
	if i := strings.IndexByte(hp, '/'); i >= 0 {
		hp = hp[:i]
	}
	host := hp
	if strings.HasPrefix(hp, "[") {
		if i := strings.IndexByte(hp, ']'); i > 0 {
			host = hp[:i+1]
		}
	} else if i := strings.LastIndexByte(hp, ':'); i >= 0 && isPortSpec(hp[i+1:]) {
		host = hp[:i]
	}
	if host == "" || isLocalHost(host) {
		return nil
	}
	return []span{{base, base + len(host), labelServer}}
}

// isPortSpec 判断是否为端口或端口范围（hysteria2 支持 443,1000-2000）。
func isPortSpec(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) && s[i] != ',' && s[i] != '-' {
			return false
		}
	}
	return true
}

func looksBase64(s string) bool {
	_, ok := decodeBase64(s)
	return ok
}

func decodeBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// ---------- 订阅内容 ----------

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

// detectBase64Subs 识别直接粘贴的 base64 订阅内容（解码后是一组分享链接）。
func detectBase64Subs(text string) []span {
	const minLen = 48
	var spans []span
	for i := 0; i < len(text); {
		if !isBase64Char(text[i]) {
			i++
			continue
		}
		s := i
		for i < len(text) && isBase64Char(text[i]) {
			i++
		}
		for n := 0; n < 2 && i < len(text) && text[i] == '='; n++ {
			i++
		}
		if i-s < minLen {
			continue
		}
		if dec, ok := decodeBase64(text[s:i]); ok && strings.Contains(dec, "://") && hasShareLink(dec) {
			spans = append(spans, span{s, i, labelSubRaw})
		}
	}
	return spans
}

func hasShareLink(s string) bool {
	for _, m := range findURLs(s) {
		if shareSchemes[m.scheme] {
			return true
		}
	}
	return false
}

// ---------- 配置字段 ----------

type yamlLine struct {
	start   int    // 行首在 text 中的偏移
	content string // 去掉行尾 \r 的整行
}

func splitLines(text string) []yamlLine {
	var lines []yamlLine
	pos := 0
	for pos <= len(text) {
		end := strings.IndexByte(text[pos:], '\n')
		var ln string
		if end < 0 {
			ln = text[pos:]
		} else {
			ln = text[pos : pos+end]
		}
		lines = append(lines, yamlLine{pos, strings.TrimSuffix(ln, "\r")})
		if end < 0 {
			break
		}
		pos += end + 1
	}
	return lines
}

// lineIndent 返回缩进宽度，以及跳过注释符号后的正文起点（isComment 表示整行是注释）。
func lineBody(ln string) (indent, bodyAt int, isComment bool) {
	i := 0
	for i < len(ln) && (ln[i] == ' ' || ln[i] == '\t') {
		i++
	}
	indent = i
	if i < len(ln) && ln[i] == '#' {
		isComment = true
		i++
		for i < len(ln) && (ln[i] == '#' || ln[i] == ' ' || ln[i] == '\t') {
			i++
		}
	}
	return indent, i, isComment
}

type stackItem struct {
	indent int
	key    string
}

// pendingBlock 表示上一行的敏感字段值为空或为块标量，值写在后续缩进更深的行里。
type pendingBlock struct {
	indent  int    // 字段所在缩进
	label   string // 占位符
	key     string
	scalar  bool // 块标量（| >）：后续缩进更深的行整体是值
	spanAt  int  // 块标量起点（-1 表示尚未开始）
	spanTo  int
	comment bool // 字段本身写在注释里（# key:）
	child   int  // 第一个子行的有效缩进（-1 表示尚未遇到）
	list    bool // 第一个子行是列表项
}

func scanProxyConfig(text string) []span {
	var spans []span
	var stack []stackItem
	var pend *pendingBlock

	flushPend := func() {
		if pend != nil && pend.scalar && pend.spanAt >= 0 {
			spans = append(spans, span{pend.spanAt, pend.spanTo, pend.label})
		}
		pend = nil
	}

	for _, ln := range splitLines(text) {
		indent, bodyAt, isComment := lineBody(ln.content)
		if bodyAt >= len(ln.content) { // 空行（含仅有 # 的行）
			continue
		}
		if pend != nil {
			// 有效缩进：注释掉的字段，其子行也在注释里，按 # 之后的正文位置比较；
			// 真实字段的子行若被注释（    # - xxx），按 # 所在列比较。
			effIndent := indent
			if pend.comment {
				effIndent = bodyAt
				if !isComment {
					effIndent = -1 // 真实行不可能是注释字段的子行
				}
			}
			if pend.scalar {
				if effIndent > pend.indent {
					s := ln.start + bodyAt
					if pend.spanAt < 0 {
						pend.spanAt = s
					}
					pend.spanTo = ln.start + len(strings.TrimRight(ln.content, " \t"))
					continue
				}
				flushPend()
			} else if effIndent > pend.indent || (effIndent == pend.indent && strings.HasPrefix(ln.content[bodyAt:], "- ")) {
				if pend.child < 0 {
					pend.child = effIndent
					pend.list = strings.HasPrefix(ln.content[bodyAt:], "-")
				}
				direct := effIndent == pend.child
				done, endPend := handlePendingChild(ln, bodyAt, isComment, direct, pend, &spans)
				if endPend {
					pend = nil
				}
				if done {
					continue
				}
				// 子行是嵌套字段（如 wireguard peers 下的 - server: …）：保留 pending 继续按字段扫描
			} else {
				flushPend()
			}
		}

		// 维护块样式的字段路径（仅非注释行）
		keyIndent, key := leadingKey(ln.content, bodyAt)
		if !isComment && key != "" {
			for len(stack) > 0 && stack[len(stack)-1].indent >= keyIndent {
				stack = stack[:len(stack)-1]
			}
		}
		path := stack
		if !isComment && key != "" {
			stack = append(stack, stackItem{keyIndent, key})
		}

		for _, kv := range scanLineKeys(ln.content, bodyAt) {
			nk := normKey(kv.key)
			label := proxyKeyLabels[nk]
			if nk == "url" && len(path) > 0 && path[0].key == "proxy-providers" &&
				((len(path) == 2 && !kv.inFlow) || (len(path) == 1 && kv.inFlow)) {
				label = labelSub
			}
			if nk == "id" && kv.kind == valScalar && isUUID(strings.TrimSpace(ln.content[kv.vs:kv.ve])) {
				label = labelSecret // Xray 的 "id" 就是 uuid
			}
			if label == "" {
				continue
			}
			switch kv.kind {
			case valScalar:
				v := ln.content[kv.vs:kv.ve]
				if keepProxyValue(nk, v) {
					continue
				}
				spans = append(spans, span{ln.start + kv.vs, ln.start + kv.ve, label})
			case valSeq:
				for _, it := range kv.items {
					v := ln.content[it[0]:it[1]]
					if keepProxyValue(nk, v) {
						continue
					}
					spans = append(spans, span{ln.start + it[0], ln.start + it[1], label})
				}
			case valMap:
			case valEmpty, valBlock:
				if nk == "url" { // url 只按单行值处理
					continue
				}
				flushPend()
				pend = &pendingBlock{indent: kv.indentHint(indent, bodyAt), label: label, key: nk,
					scalar: kv.kind == valBlock, spanAt: -1, comment: isComment, child: -1}
			}
		}
	}
	flushPend()
	return spans
}

// handlePendingChild 处理空值敏感字段的子行：列表项标量、多行标量、users 映射。
// done 表示本行已作为值处理完毕；endPend 表示值已读完、应结束 pending。
// direct 表示本行是字段的直接子行（而非更深层的嵌套）。
func handlePendingChild(ln yamlLine, bodyAt int, isComment, direct bool, pend *pendingBlock, spans *[]span) (done, endPend bool) {
	body := ln.content[bodyAt:]
	add := func(s, e int, label string) {
		if !keepProxyValue(pend.key, ln.content[s:e]) {
			*spans = append(*spans, span{ln.start + s, ln.start + e, label})
		}
	}
	if strings.HasPrefix(body, "- ") || body == "-" {
		at := bodyAt + 1
		for at < len(ln.content) && ln.content[at] == ' ' {
			at++
		}
		if at >= len(ln.content) {
			return true, false
		}
		if _, k := leadingKey(ln.content, at); k != "" {
			return false, false // - key: value 形式的映射项，交给字段扫描
		}
		if s, e, ok := scalarAt(ln.content, at, false); ok {
			add(s, e, pend.label)
		}
		return true, false
	}
	if _, k := leadingKey(ln.content, bodyAt); k != "" {
		if pend.key == "users" && direct && !pend.list { // users 映射：用户名: 密码 / uuid: 密码
			kvs := scanLineKeys(ln.content, bodyAt)
			if len(kvs) > 0 && kvs[0].kind == valScalar && proxyKeyLabels[normKey(kvs[0].key)] == "" {
				ks := kvs[0].keyAt
				if c := ln.content[ks]; c == '"' || c == '\'' {
					ks++
				}
				*spans = append(*spans, span{ln.start + ks, ln.start + ks + len(kvs[0].key), labelUser})
				add(kvs[0].vs, kvs[0].ve, pend.label)
				return true, false
			}
		}
		return false, false
	}
	if isComment || !direct {
		return true, false // 注释里的说明文字 / 更深层内容，不当作值
	}
	// 多行普通标量：key:\n  "value" # 注释
	if s, e, ok := scalarAt(ln.content, bodyAt, false); ok {
		add(s, e, pend.label)
	}
	return true, true
}

// keepProxyValue 判断字段值是否无需脱敏（空值、布尔、本机地址、模板变量等）。
func keepProxyValue(key, v string) bool {
	v = strings.TrimSpace(v)
	lv := strings.ToLower(v)
	if proxyBenignValues[lv] || isTemplateVar(v) {
		return true
	}
	switch key {
	case "server", "address", "ip", "ipv6", "peers", "endpoint":
		return isLocalHost(v)
	case "auth": // openvpn auth: SHA256 是摘要算法
		return strings.HasPrefix(lv, "sha") || lv == "md5"
	}
	return false
}

func normKey(k string) string {
	return strings.ReplaceAll(strings.ToLower(k), "_", "-")
}

// ---------- 行内解析 ----------

const (
	valScalar = iota
	valEmpty
	valBlock
	valSeq
	valMap
)

type lineKV struct {
	key    string
	keyAt  int // 字段名在行内的偏移
	kind   int
	vs, ve int      // valScalar：值区间（不含引号）
	items  [][2]int // valSeq：各元素区间
	inFlow bool
}

// indentHint 返回字段的缩进：行首字段取字段名位置（兼容 "- key:"），流样式取行缩进。
func (kv lineKV) indentHint(indent, bodyAt int) int {
	if kv.inFlow {
		return indent
	}
	return kv.keyAt
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// leadingKey 读取行首（跳过 "- " 列表标记）的字段名，返回字段名所在列与字段名。
func leadingKey(ln string, at int) (int, string) {
	for at+1 < len(ln) && ln[at] == '-' && ln[at+1] == ' ' {
		at += 2
		for at < len(ln) && ln[at] == ' ' {
			at++
		}
	}
	k, _, ok := readKey(ln, at)
	if !ok {
		return 0, ""
	}
	return at, k
}

// readKey 在 at 处读取 key: 结构，返回字段名与冒号之后的位置。
func readKey(ln string, at int) (string, int, bool) {
	if at >= len(ln) {
		return "", 0, false
	}
	var key string
	i := at
	quoted := false
	if q := ln[i]; q == '"' || q == '\'' {
		j := strings.IndexByte(ln[i+1:], q)
		if j <= 0 {
			return "", 0, false
		}
		key = ln[i+1 : i+1+j]
		for k := 0; k < len(key); k++ {
			if !isKeyChar(key[k]) {
				return "", 0, false
			}
		}
		i += j + 2
		quoted = true
	} else {
		for i < len(ln) && isKeyChar(ln[i]) {
			i++
		}
		if i == at {
			return "", 0, false
		}
		key = ln[at:i]
	}
	for i < len(ln) && (ln[i] == ' ' || ln[i] == '\t') {
		i++
	}
	if i >= len(ln) || ln[i] != ':' {
		return "", 0, false
	}
	i++
	// YAML 中裸字段名的冒号后必须是空白或行尾（区分 http://、host:443 等）
	if !quoted && i < len(ln) && ln[i] != ' ' && ln[i] != '\t' && ln[i] != ',' && ln[i] != '}' {
		return "", 0, false
	}
	return key, i, true
}

// scalarAt 从 at 开始读一个标量值，返回值区间（引号值不含引号）。inFlow 时遇 , } ] 结束。
func scalarAt(ln string, at int, inFlow bool) (int, int, bool) {
	for at < len(ln) && (ln[at] == ' ' || ln[at] == '\t') {
		at++
	}
	if at >= len(ln) {
		return 0, 0, false
	}
	switch q := ln[at]; q {
	case '"', '\'':
		i := at + 1
		for i < len(ln) {
			if q == '"' && ln[i] == '\\' {
				i += 2
				continue
			}
			if ln[i] == q {
				if q == '\'' && i+1 < len(ln) && ln[i+1] == '\'' {
					i += 2
					continue
				}
				return at + 1, i, true
			}
			i++
		}
		return at + 1, len(ln), true // 未闭合，按到行尾处理
	case '#':
		return 0, 0, false
	}
	end := len(ln)
	for i := at; i < len(ln); i++ {
		c := ln[i]
		if inFlow && (c == ',' || c == '}' || c == ']') {
			end = i
			break
		}
		if c == '#' && i > at && (ln[i-1] == ' ' || ln[i-1] == '\t') {
			end = i
			break
		}
	}
	v := strings.TrimRight(ln[at:end], " \t")
	if !inFlow {
		v = strings.TrimRight(v, ",") // JSON 行尾逗号
	}
	if v == "" {
		return 0, 0, false
	}
	return at, at + len(v), true
}

// skipQuoted 返回跳过 at 处引号串之后的位置。
func skipQuoted(ln string, at int) int {
	q := ln[at]
	i := at + 1
	for i < len(ln) {
		if q == '"' && ln[i] == '\\' {
			i += 2
			continue
		}
		if ln[i] == q {
			return i + 1
		}
		i++
	}
	return len(ln)
}

// scanLineKeys 找出一行中所有 key: value（行首字段，以及流样式 {…} / JSON 里的字段）。
func scanLineKeys(ln string, bodyAt int) []lineKV {
	var out []lineKV
	depth := 0 // 流样式嵌套深度（{ 与 [）
	keyPos := true
	i := bodyAt
	for i < len(ln) {
		c := ln[i]
		if keyPos {
			// 跳过列表标记与空白
			for i < len(ln) && (ln[i] == ' ' || ln[i] == '\t') {
				i++
			}
			for i+1 < len(ln) && ln[i] == '-' && ln[i+1] == ' ' {
				i += 2
				for i < len(ln) && ln[i] == ' ' {
					i++
				}
			}
			keyPos = false
			if key, after, ok := readKey(ln, i); ok {
				kv := lineKV{key: key, keyAt: i, inFlow: depth > 0}
				i = parseValue(ln, after, depth > 0, &kv)
				out = append(out, kv)
				if kv.kind == valMap {
					depth++
					i++
					keyPos = true
				}
				continue
			}
			continue
		}
		switch c {
		case '"', '\'':
			i = skipQuoted(ln, i)
			continue
		case '{':
			depth++
			keyPos = true
		case '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth > 0 {
				keyPos = true
			}
		case '#':
			if depth == 0 && (i == 0 || ln[i-1] == ' ' || ln[i-1] == '\t') {
				return out // 行尾注释
			}
		}
		i++
	}
	return out
}

// parseValue 解析冒号后的值，填充 kv，返回扫描应继续的位置。
func parseValue(ln string, at int, inFlow bool, kv *lineKV) int {
	i := at
	for i < len(ln) && (ln[i] == ' ' || ln[i] == '\t') {
		i++
	}
	if i >= len(ln) || (ln[i] == '#' && i > at) {
		kv.kind = valEmpty
		return len(ln)
	}
	switch ln[i] {
	case '|', '>':
		kv.kind = valBlock
		return len(ln)
	case '{':
		kv.kind = valMap // 嵌套映射：由调用方继续扫描其中的字段
		return i
	case '[':
		kv.kind = valSeq
		j := i + 1
		for j < len(ln) {
			for j < len(ln) && (ln[j] == ' ' || ln[j] == ',') {
				j++
			}
			if j >= len(ln) || ln[j] == ']' {
				break
			}
			if ln[j] == '[' || ln[j] == '{' { // 嵌套结构不深入
				break
			}
			s, e, ok := scalarAt(ln, j, true)
			if !ok {
				break
			}
			kv.items = append(kv.items, [2]int{s, e})
			j = e
			if j < len(ln) && (ln[j] == '"' || ln[j] == '\'') {
				j++
			}
			for j < len(ln) && ln[j] != ',' && ln[j] != ']' {
				j++
			}
		}
		return j
	}
	s, e, ok := scalarAt(ln, i, inFlow)
	if !ok {
		kv.kind = valEmpty
		return len(ln)
	}
	kv.kind = valScalar
	kv.vs, kv.ve = s, e
	if e < len(ln) && (ln[e] == '"' || ln[e] == '\'') {
		e++
	}
	return e
}
