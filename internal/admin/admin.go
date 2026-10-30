// Package admin 是中继的管理后台：管理员用 passkey 登录，在网页上出邀请码、看哪些主机在线、删主机。
//
// 挂在中继控制面的域名上（HERDR_RELAY_DOMAIN / DIALHOME_DOMAIN），和按 SNI 透传的那条路完全分开 ——
// 主机名的流量根本不进这个进程的 HTTP 层。
//
// 只有一个管理员（超级管理员），没有注册：第一把 passkey 靠 VPS 上 `dialhome admin init` 印出的一次性
// 链接注册，能敲那条命令的人本来就有这台机器的 shell。为什么是 passkey 不是密码：服务端只存公钥，
// admin.json 泄露了也登不进来；也没有「密码被撞库」这条路。
package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/zbysir/dialhome/relay"
)

// SessionTTL：登录一次管用多久。到期了就再刷一次 passkey —— 一下 Face ID 的事，没必要给长。
const SessionTTL = 24 * time.Hour

const cookieName = "dialhome_admin"

// ceremonyTTL：拿到 challenge 到提交之间的时限。
const ceremonyTTL = 2 * time.Minute

type Config struct {
	// Domain 是中继控制面的域名，也是 passkey 的 RPID。浏览器里的 origin 必须是 https://<Domain>。
	Domain string
	Data   Data
	Relay  *relay.Relay
	// UI 是前端产物（index.html + assets/）。nil 时只有 /api/。
	UI fs.FS
	// Origin 只给测试用：默认 https://<Domain>
	Origin string
}

type Admin struct {
	cfg Config
	w   *webauthn.WebAuthn
	now func() time.Time

	mu   sync.Mutex
	cers map[string]*ceremony
}

type ceremony struct {
	data *webauthn.SessionData
	kind string // setup / login / add
	tok  string // setup 那种：令牌的哈希，finish 时再核一次（期间可能被 reset 掉）
	exp  time.Time
}

func New(cfg Config) (*Admin, error) {
	if cfg.Origin == "" {
		cfg.Origin = "https://" + cfg.Domain
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID: cfg.Domain, RPDisplayName: "dialhome", RPOrigins: []string{cfg.Origin},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey 配置不对（域名 %q）: %w", cfg.Domain, err)
	}
	return &Admin{cfg: cfg, w: w, now: time.Now, cers: map[string]*ceremony{}}, nil
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// 后台页面：不许被嵌、不许被收录、不许外链脚本。
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow")

	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
		a.api(w, r)
		return
	}
	a.static(w, r)
}

func (a *Admin) static(w http.ResponseWriter, r *http.Request) {
	if a.cfg.UI == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "robots.txt" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
		return
	}
	if p != "" && !strings.HasPrefix(p, "assets/") && p != "favicon.svg" {
		p = "" // 单页应用：别的路径一律回 index
	}
	if p == "" {
		p = "index.html"
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	http.ServeFileFS(w, r, a.cfg.UI, p)
}

/* ------------------------------------------------------------------ API */

func (a *Admin) api(w http.ResponseWriter, r *http.Request) {
	// 会改东西的请求一律核 Origin：会话 cookie 已经是 SameSite=Strict，这是第二道。
	// fetch 发 POST / DELETE 时浏览器一定带 Origin，不带的不是我们的页面。
	if r.Method != http.MethodGet && r.Header.Get("Origin") != a.cfg.Origin {
		fail(w, http.StatusForbidden, "来源不对")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	route := r.Method + " " + path

	// 不用登录的几条
	switch route {
	case "GET /state":
		a.state(w, r)
		return
	case "POST /setup/begin":
		a.setupBegin(w, r)
		return
	case "POST /setup/finish":
		a.setupFinish(w, r)
		return
	case "POST /login/begin":
		a.loginBegin(w, r)
		return
	case "POST /login/finish":
		a.loginFinish(w, r)
		return
	case "POST /logout":
		a.clearCookie(w)
		ok(w, nil)
		return
	}

	cred, f := a.session(r)
	if cred == "" {
		fail(w, http.StatusUnauthorized, "没登录或者登录过期了")
		return
	}
	switch {
	case route == "GET /hosts":
		a.hosts(w)
	case route == "POST /invites":
		a.invite(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/invites/"):
		a.revokeInvite(w, strings.TrimPrefix(path, "/invites/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/hosts/"):
		a.removeHost(w, strings.TrimPrefix(path, "/hosts/"))
	case route == "GET /passkeys":
		a.passkeys(w, f, cred)
	case route == "POST /passkeys/begin":
		a.beginRegister(w, "add", "")
	case route == "POST /passkeys/finish":
		a.addFinish(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/passkeys/"):
		a.deletePasskey(w, strings.TrimPrefix(path, "/passkeys/"))
	default:
		fail(w, http.StatusNotFound, "没有这个接口")
	}
}

func (a *Admin) state(w http.ResponseWriter, r *http.Request) {
	f, err := a.cfg.Data.Read()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	cred, _ := a.session(r)
	ok(w, map[string]any{
		"loggedIn":   cred != "",
		"hasPasskey": len(f.Keys) > 0,
		"domain":     a.cfg.Domain,
	})
}

/* ------------------------------------------------------------------ 主机 / 邀请码 */

type hostView struct {
	Name    string         `json:"name"`
	Created time.Time      `json:"created"`
	Online  *relay.Online  `json:"online"`
}

func (a *Admin) hosts(w http.ResponseWriter) {
	hs, err := a.cfg.Data.Store.Hosts()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ivs, err := a.cfg.Data.Store.Invites()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	on := map[string]relay.Online{}
	if a.cfg.Relay != nil {
		on = a.cfg.Relay.OnlineHosts()
	}
	out := make([]hostView, 0, len(hs))
	for _, h := range hs {
		v := hostView{Name: h.Name, Created: h.Created}
		if o, yes := on[h.Name]; yes {
			v.Online = &o
		}
		out = append(out, v)
	}
	ok(w, map[string]any{"relay": a.cfg.Origin, "hosts": out, "invites": ivs})
}

func (a *Admin) invite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "请求读不懂")
		return
	}
	host, err := relay.CleanHost(req.Host)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if host == a.cfg.Domain {
		fail(w, http.StatusBadRequest, host+" 是中继自己的名字，不能注册成主机")
		return
	}
	existing, err := a.cfg.Data.Store.Lookup(host)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	code, err := a.cfg.Data.Store.NewInvite(host)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, map[string]any{
		"host": host, "code": code, "relay": a.cfg.Origin,
		"expires": a.now().Add(relay.InviteTTL),
		// 这个名字已经有主机了：码用掉就会顶掉原来那台（重装系统丢了钥匙时就靠这个认领回来）
		"replaces": existing != nil,
	})
}

func (a *Admin) revokeInvite(w http.ResponseWriter, host string) {
	n, err := a.cfg.Data.Store.RevokeInvites(host)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, map[string]any{"revoked": n})
}

func (a *Admin) removeHost(w http.ResponseWriter, host string) {
	found, err := a.cfg.Data.Store.Remove(host)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		fail(w, http.StatusNotFound, "没有 "+host+" 这台主机")
		return
	}
	if a.cfg.Relay != nil {
		a.cfg.Relay.Kick(host)
	}
	ok(w, nil)
}

/* ------------------------------------------------------------------ passkey */

type user struct {
	handle []byte
	keys   []*Passkey
}

func (u *user) WebAuthnID() []byte          { return u.handle }
func (u *user) WebAuthnName() string        { return "admin" }
func (u *user) WebAuthnDisplayName() string { return "dialhome 管理员" }
func (u *user) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.keys))
	for _, k := range u.keys {
		out = append(out, k.Cred)
	}
	return out
}

func regOpts() []webauthn.RegistrationOption {
	return []webauthn.RegistrationOption{
		// discoverable：登录时不用先输用户名，手机上就是「点一下 → Face ID」
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	}
}

// beginRegister 给 setup 和「再加一把」共用。handle 第一次用时才落盘，所以这里先 Update 一次。
func (a *Admin) beginRegister(w http.ResponseWriter, kind, tok string) {
	var u *user
	if err := a.cfg.Data.Update(func(f *file) error {
		u = &user{handle: f.Handle, keys: f.Keys}
		return nil
	}); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	opts, sd, err := a.w.BeginRegistration(u, regOpts()...)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, map[string]any{"options": opts, "ceremony": a.stash(sd, kind, tok)})
}

// finishRegister 核完签名把新 passkey 记下来。check 在锁里再核一次资格（setup 令牌这段时间里可能
// 被 reset 作废了）。
func (a *Admin) finishRegister(r *http.Request, kind string, check func(f *file, c *ceremony) error) (*Passkey, error) {
	c := a.take(r.URL.Query().Get("ceremony"), kind)
	if c == nil {
		return nil, errors.New("这次注册已经过期了，重新点一次")
	}
	var k *Passkey
	err := a.cfg.Data.Update(func(f *file) error {
		if err := check(f, c); err != nil {
			return err
		}
		cred, err := a.w.FinishRegistration(&user{handle: f.Handle, keys: f.Keys}, *c.data, r)
		if err != nil {
			return fmt.Errorf("passkey 没验过：%w", err)
		}
		now := a.now()
		k = &Passkey{ID: hex.EncodeToString(randBytes(6)), Label: labelFromUA(r.UserAgent()),
			Created: now, LastUsed: now, Cred: *cred}
		f.Keys = append(f.Keys, k)
		return nil
	})
	return k, err
}

func (a *Admin) setupBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "请求读不懂")
		return
	}
	th := hashToken(strings.TrimSpace(req.Token))
	f, err := a.cfg.Data.Read()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !f.setupOK(th, a.now()) {
		fail(w, http.StatusForbidden, "这个链接无效（过期了、用过了，或者被 reset 掉了）：在服务器上重新跑一次 dialhome admin init")
		return
	}
	a.beginRegister(w, "setup", th)
}

func (a *Admin) setupFinish(w http.ResponseWriter, r *http.Request) {
	k, err := a.finishRegister(r, "setup", func(f *file, c *ceremony) error {
		if !f.setupOK(c.tok, a.now()) {
			return errors.New("这个链接已经失效了：在服务器上重新跑一次 dialhome admin init")
		}
		f.Setup = nil // 用一次就废
		return nil
	})
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a.issue(w, k.ID)
	ok(w, map[string]any{"label": k.Label})
}

func (a *Admin) addFinish(w http.ResponseWriter, r *http.Request) {
	k, err := a.finishRegister(r, "add", func(*file, *ceremony) error { return nil })
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ok(w, map[string]any{"label": k.Label})
}

func (a *Admin) loginBegin(w http.ResponseWriter, _ *http.Request) {
	f, err := a.cfg.Data.Read()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(f.Keys) == 0 {
		fail(w, http.StatusConflict, "还没有管理员 passkey：在服务器上跑 dialhome admin init")
		return
	}
	opts, sd, err := a.w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, map[string]any{"options": opts, "ceremony": a.stash(sd, "login", "")})
}

func (a *Admin) loginFinish(w http.ResponseWriter, r *http.Request) {
	c := a.take(r.URL.Query().Get("ceremony"), "login")
	if c == nil {
		fail(w, http.StatusBadRequest, "这次验证已经过期了，重新点一次")
		return
	}
	var id string
	err := a.cfg.Data.Update(func(f *file) error {
		u := &user{handle: f.Handle, keys: f.Keys}
		// 只有一个「用户」，回调总是它；真正的判断在签名校验里
		cred, err := a.w.FinishDiscoverableLogin(
			func(_, _ []byte) (webauthn.User, error) { return u, nil }, *c.data, r)
		if err != nil {
			return fmt.Errorf("passkey 没验过：%w", err)
		}
		for _, k := range f.Keys {
			if string(k.Cred.ID) == string(cred.ID) {
				k.Cred = *cred // 计数器要写回去：库靠它发现被克隆的认证器
				k.LastUsed = a.now()
				id = k.ID
				return nil
			}
		}
		return errors.New("这把 passkey 不在名单里（可能已经被删掉了）")
	})
	if err != nil {
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.issue(w, id)
	ok(w, nil)
}

type passkeyView struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
	Current  bool      `json:"current"`
}

func (a *Admin) passkeys(w http.ResponseWriter, f *file, cur string) {
	out := make([]passkeyView, 0, len(f.Keys))
	for _, k := range f.Keys {
		out = append(out, passkeyView{ID: k.ID, Label: k.Label, Created: k.Created, LastUsed: k.LastUsed, Current: k.ID == cur})
	}
	ok(w, out)
}

func (a *Admin) deletePasskey(w http.ResponseWriter, id string) {
	err := a.cfg.Data.Update(func(f *file) error {
		hit := -1
		for i, k := range f.Keys {
			if k.ID == id {
				hit = i
			}
		}
		if hit < 0 {
			return errors.New("没有这把 passkey")
		}
		if len(f.Keys) == 1 {
			// 删了最后一把就谁都进不来了，只能上服务器 init —— 那就让人明着去做
			return errors.New("这是最后一把 passkey，删了就进不来了。要换设备先加一把新的再删；全清掉用服务器上的 dialhome admin reset")
		}
		f.Keys = append(f.Keys[:hit], f.Keys[hit+1:]...)
		return nil
	})
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ok(w, nil)
}

func (a *Admin) stash(sd *webauthn.SessionData, kind, tok string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for id, c := range a.cers {
		if now.After(c.exp) {
			delete(a.cers, id)
		}
	}
	id := hex.EncodeToString(randBytes(16))
	a.cers[id] = &ceremony{data: sd, kind: kind, tok: tok, exp: now.Add(ceremonyTTL)}
	return id
}

// take：challenge 用一次就废，而且种类要对得上（拿登录的 challenge 去走注册不行）。
func (a *Admin) take(id, kind string) *ceremony {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.cers[id]
	delete(a.cers, id)
	if c == nil || c.kind != kind || a.now().After(c.exp) {
		return nil
	}
	return c
}

/* ------------------------------------------------------------------ 会话 */

// 会话是签名 cookie（不存服务端）：`<passkey id>.<到期 unix>.<hmac>`。
// 每次请求都重读 admin.json 核三样：签名（会话密钥，reset 一换全废）、没过期、那把 passkey 还在
// （删掉一把 passkey = 用它登录的会话当场作废）。
func (a *Admin) issue(w http.ResponseWriter, keyID string) {
	f, err := a.cfg.Data.Read()
	if err != nil {
		return
	}
	exp := a.now().Add(SessionTTL)
	body := keyID + "." + strconv.FormatInt(exp.Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: body + "." + mac(f.SessionKey, body), Path: "/",
		Expires: exp, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (a *Admin) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

// session 返回登录用的那把 passkey 的 id（没登录是空串）和顺手读到的 admin.json。
func (a *Admin) session(r *http.Request) (string, *file) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", nil
	}
	f, err := a.cfg.Data.Read()
	if err != nil || len(f.SessionKey) == 0 {
		return "", nil
	}
	body := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(mac(f.SessionKey, body)), []byte(parts[2])) {
		return "", nil
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || a.now().Unix() >= exp {
		return "", nil
	}
	for _, k := range f.Keys {
		if k.ID == parts[0] {
			return k.ID, f
		}
	}
	return "", nil
}

func mac(key []byte, body string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

/* ------------------------------------------------------------------ 小工具 */

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if v == nil {
		v = map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// labelFromUA 给 passkey 起个人认得出的名字（「iPhone · Safari」），列表里分得清哪把是哪台设备的。
func labelFromUA(ua string) string {
	dev := "未知设备"
	switch {
	case strings.Contains(ua, "iPhone"):
		dev = "iPhone"
	case strings.Contains(ua, "iPad"):
		dev = "iPad"
	case strings.Contains(ua, "Android"):
		dev = "Android"
	case strings.Contains(ua, "Macintosh"):
		dev = "Mac"
	case strings.Contains(ua, "Windows"):
		dev = "Windows"
	case strings.Contains(ua, "Linux"):
		dev = "Linux"
	}
	br := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		br = "Edge"
	case strings.Contains(ua, "Firefox/"):
		br = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/"):
		br = "Chrome"
	case strings.Contains(ua, "Safari/"):
		br = "Safari"
	}
	if br == "" {
		return dev
	}
	return dev + " · " + br
}
