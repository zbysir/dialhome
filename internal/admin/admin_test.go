package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/zbysir/dialhome/relay"
)

const (
	domain = "relay.test"
	origin = "https://relay.test"
)

func newAdmin(t *testing.T) *Admin {
	t.Helper()
	a, err := New(Config{Domain: domain, Data: Data{Store: relay.Store{Dir: t.TempDir()}}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// browser 是「一个浏览器 + 一把软件 passkey」：记 cookie，会做 WebAuthn 的注册和登录。
type browser struct {
	t      *testing.T
	a      *Admin
	cookie string
	key    *ecdsa.PrivateKey
	credID []byte
	handle []byte
}

func newBrowser(t *testing.T, a *Admin) *browser {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &browser{t: t, a: a, key: k, credID: id}
}

func (b *browser) do(method, path string, body any) (int, map[string]any) {
	b.t.Helper()
	var rd *bytes.Reader
	switch v := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(v)
	default:
		j, _ := json.Marshal(v)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/605.1.15")
	if b.cookie != "" {
		req.Header.Set("Cookie", b.cookie)
	}
	w := httptest.NewRecorder()
	b.a.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			b.cookie = c.Name + "=" + c.Value
			if c.MaxAge < 0 {
				b.cookie = ""
			}
		}
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func challengeOf(t *testing.T, begin map[string]any) string {
	t.Helper()
	pk := begin["options"].(map[string]any)["publicKey"].(map[string]any)
	return pk["challenge"].(string)
}

func rpHash() []byte { h := sha256.Sum256([]byte(domain)); return h[:] }

// register 走一遍 begin → 认证器出 attestation → finish。
func (b *browser) register(beginPath, finishPath string, beginBody any) (int, map[string]any) {
	b.t.Helper()
	code, begin := b.do("POST", beginPath, beginBody)
	if code != 200 {
		return code, begin
	}
	pk := begin["options"].(map[string]any)["publicKey"].(map[string]any)
	b.handle, _ = base64.RawURLEncoding.DecodeString(pk["user"].(map[string]any)["id"].(string))

	cd, _ := json.Marshal(map[string]string{"type": "webauthn.create", "challenge": challengeOf(b.t, begin), "origin": origin})
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: b.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: b.key.PublicKey.Y.FillBytes(make([]byte, 32))})
	ad := append(rpHash(), 0x45, 0, 0, 0, 0) // UP | UV | AT，计数 0
	ad = append(ad, make([]byte, 16)...)     // aaguid
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(b.credID)))
	ad = append(append(ad, b.credID...), cose...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})

	resp, _ := json.Marshal(map[string]any{
		"id": b64(b.credID), "rawId": b64(b.credID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(cd), "attestationObject": b64(att)},
	})
	return b.do("POST", finishPath+"?ceremony="+begin["ceremony"].(string), resp)
}

var counter uint32

func (b *browser) login() (int, map[string]any) {
	b.t.Helper()
	code, begin := b.do("POST", "/api/login/begin", nil)
	if code != 200 {
		return code, begin
	}
	cd, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": challengeOf(b.t, begin), "origin": origin})
	counter++
	ad := binary.BigEndian.AppendUint32(append(rpHash(), 0x05), counter) // UP | UV
	h := sha256.Sum256(cd)
	sig, _ := ecdsa.SignASN1(rand.Reader, b.key, sha256Sum(append(append([]byte{}, ad...), h[:]...)))
	resp, _ := json.Marshal(map[string]any{
		"id": b64(b.credID), "rawId": b64(b.credID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(cd), "authenticatorData": b64(ad),
			"signature": b64(sig), "userHandle": b64(b.handle)},
	})
	return b.do("POST", "/api/login/finish?ceremony="+begin["ceremony"].(string), resp)
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func setupAdmin(t *testing.T, a *Admin) *browser {
	t.Helper()
	tok, err := a.cfg.Data.NewSetup()
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, a)
	if code, out := b.register("/api/setup/begin", "/api/setup/finish", map[string]string{"token": tok}); code != 200 {
		t.Fatalf("setup: %d %v", code, out)
	}
	return b
}

// 整条路：init 链接注册 → 已登录 → 出邀请码 → 主机拿码注册 → 列表里有它 → 删掉 → 登出 → passkey 再登录。
func TestSetupInviteLogin(t *testing.T) {
	a := newAdmin(t)
	b := setupAdmin(t, a)

	if _, st := b.do("GET", "/api/state", nil); st["loggedIn"] != true {
		t.Fatalf("注册完应当已登录：%v", st)
	}
	code, iv := b.do("POST", "/api/invites", map[string]string{"host": "Mac.H.Test."})
	if code != 200 || iv["host"] != "mac.h.test" || iv["code"] == "" || iv["replaces"] != false {
		t.Fatalf("出邀请码：%d %v", code, iv)
	}
	if err := a.cfg.Data.Store.Redeem("mac.h.test", iv["code"].(string), make([]byte, 32)); err != nil {
		t.Fatalf("后台出的码主机用不了：%v", err)
	}
	_, hs := b.do("GET", "/api/hosts", nil)
	if l := hs["hosts"].([]any); len(l) != 1 || l[0].(map[string]any)["name"] != "mac.h.test" {
		t.Fatalf("主机列表：%v", hs)
	}
	if code, _ := b.do("DELETE", "/api/hosts/mac.h.test", nil); code != 200 {
		t.Fatal("删主机失败")
	}
	if h, _ := a.cfg.Data.Store.Lookup("mac.h.test"); h != nil {
		t.Fatal("删了还在")
	}

	b.do("POST", "/api/logout", nil)
	if code, _ := b.do("GET", "/api/hosts", nil); code != 401 {
		t.Fatalf("登出之后还能看：%d", code)
	}
	if code, out := b.login(); code != 200 {
		t.Fatalf("passkey 登录：%d %v", code, out)
	}
	if code, _ := b.do("GET", "/api/hosts", nil); code != 200 {
		t.Fatal("登录之后看不了")
	}
}

// init 链接只能用一次；reset 之后旧链接、旧会话都作废。
func TestSetupTokenSingleUseAndReset(t *testing.T) {
	a := newAdmin(t)
	tok, _ := a.cfg.Data.NewSetup()
	b := newBrowser(t, a)
	if code, _ := b.register("/api/setup/begin", "/api/setup/finish", map[string]string{"token": tok}); code != 200 {
		t.Fatal("第一次应当成功")
	}
	other := newBrowser(t, a)
	if code, _ := other.register("/api/setup/begin", "/api/setup/finish", map[string]string{"token": tok}); code != 403 {
		t.Fatalf("同一个链接用了第二次：%d", code)
	}
	if code, _ := other.register("/api/setup/begin", "/api/setup/finish", map[string]string{"token": "nope"}); code != 403 {
		t.Fatalf("瞎编的令牌：%d", code)
	}

	if n, _ := a.cfg.Data.Reset(); n != 1 {
		t.Fatalf("reset 应当删掉 1 把，删了 %d", n)
	}
	if code, _ := b.do("GET", "/api/hosts", nil); code != 401 {
		t.Fatalf("reset 之后旧会话还能用：%d", code)
	}
	if code, _ := b.do("POST", "/api/login/begin", nil); code != 409 {
		t.Fatalf("没有 passkey 时登录应当是 409：%d", code)
	}
}

// begin 之后 reset 掉了令牌，finish 不能照样注册成功。
func TestSetupRevokedMidCeremony(t *testing.T) {
	a := newAdmin(t)
	tok, _ := a.cfg.Data.NewSetup()
	b := newBrowser(t, a)
	code, begin := b.do("POST", "/api/setup/begin", map[string]string{"token": tok})
	if code != 200 {
		t.Fatal(begin)
	}
	a.cfg.Data.Reset()
	cd, _ := json.Marshal(map[string]string{"type": "webauthn.create", "challenge": challengeOf(t, begin), "origin": origin})
	resp, _ := json.Marshal(map[string]any{"id": b64(b.credID), "rawId": b64(b.credID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64(cd), "attestationObject": b64([]byte{0xa0})}})
	if code, _ := b.do("POST", "/api/setup/finish?ceremony="+begin["ceremony"].(string), resp); code == 200 {
		t.Fatal("令牌被 reset 之后还注册成功了")
	}
	if f, _ := a.cfg.Data.Read(); len(f.Keys) != 0 {
		t.Fatal("多出了一把 passkey")
	}
}

// 没登录什么都看不了；外站来的写请求一律挡。
func TestGuards(t *testing.T) {
	a := newAdmin(t)
	b := setupAdmin(t, a)
	anon := newBrowser(t, a)
	for _, p := range []string{"/api/hosts", "/api/passkeys"} {
		if code, _ := anon.do("GET", p, nil); code != 401 {
			t.Errorf("%s 没登录也能看：%d", p, code)
		}
	}
	if code, _ := anon.do("POST", "/api/invites", map[string]string{"host": "x.test"}); code != 401 {
		t.Errorf("没登录也能出邀请码：%d", code)
	}

	req := httptest.NewRequest("POST", "/api/invites", strings.NewReader(`{"host":"evil.test"}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Cookie", b.cookie)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("外站 Origin 的写请求没挡住：%d", w.Code)
	}

	// 改过的 cookie
	b.cookie = strings.Replace(b.cookie, ".", ".9", 1)
	if code, _ := b.do("GET", "/api/hosts", nil); code != 401 {
		t.Fatalf("改过的 cookie 还能用：%d", code)
	}
}

// 中继自己的名字不能出邀请码；已注册的名字出码要标出「会顶掉」。
func TestInviteRules(t *testing.T) {
	a := newAdmin(t)
	b := setupAdmin(t, a)
	if code, _ := b.do("POST", "/api/invites", map[string]string{"host": domain}); code != 400 {
		t.Fatalf("给中继自己的名字出了码：%d", code)
	}
	if code, _ := b.do("POST", "/api/invites", map[string]string{"host": "1.2.3.4"}); code != 400 {
		t.Fatalf("给 IP 出了码：%d", code)
	}
	_, iv := b.do("POST", "/api/invites", map[string]string{"host": "pc.h.test"})
	a.cfg.Data.Store.Redeem("pc.h.test", iv["code"].(string), make([]byte, 32))
	if _, iv := b.do("POST", "/api/invites", map[string]string{"host": "pc.h.test"}); iv["replaces"] != true {
		t.Fatalf("已注册的名字没标 replaces：%v", iv)
	}
	_, hs := b.do("GET", "/api/hosts", nil)
	if l := hs["invites"].([]any); len(l) != 1 {
		t.Fatalf("待用的邀请码：%v", hs["invites"])
	}
	if _, out := b.do("DELETE", "/api/invites/pc.h.test", nil); out["revoked"] != float64(1) {
		t.Fatalf("作废邀请码：%v", out)
	}
}

// 最后一把 passkey 删不掉；删掉一把，用它登录的会话当场作废。
func TestPasskeyDelete(t *testing.T) {
	a := newAdmin(t)
	b := setupAdmin(t, a)
	code, list := doList(b)
	if code != 200 || len(list) != 1 || list[0]["current"] != true || list[0]["label"] != "iPhone · Safari" {
		t.Fatalf("passkey 列表：%d %v", code, list)
	}
	if code, _ := b.do("DELETE", "/api/passkeys/"+list[0]["id"].(string), nil); code != 400 {
		t.Fatalf("最后一把被删掉了：%d", code)
	}

	// 已登录时再加一把（另一台设备）
	c := newBrowser(t, a)
	c.cookie = b.cookie
	if code, out := c.register("/api/passkeys/begin", "/api/passkeys/finish", nil); code != 200 {
		t.Fatalf("加第二把：%d %v", code, out)
	}
	_, list = doList(b)
	if len(list) != 2 {
		t.Fatalf("应当有两把：%v", list)
	}
	if code, _ := b.do("DELETE", "/api/passkeys/"+list[0]["id"].(string), nil); code != 200 {
		t.Fatal("删第一把失败")
	}
	if code, _ := b.do("GET", "/api/hosts", nil); code != 401 {
		t.Fatalf("删掉的那把登录的会话还能用：%d", code)
	}
	if code, out := c.login(); code != 200 {
		t.Fatalf("第二把登录：%d %v", code, out)
	}
}

func doList(b *browser) (int, []map[string]any) {
	req := httptest.NewRequest("GET", "/api/passkeys", nil)
	req.Header.Set("Cookie", b.cookie)
	w := httptest.NewRecorder()
	b.a.ServeHTTP(w, req)
	var out []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestStaticHeaders(t *testing.T) {
	a := newAdmin(t)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Header().Get("X-Robots-Tag") == "" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("安全头没带上：%v", w.Header())
	}
	var _ http.Handler = a
}
