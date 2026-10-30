package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/zbysir/dialhome/relay"
)

// admin.json：后台的全部状态，和主机表放在同一个数据目录、拿同一把文件锁
// （命令行 `dialhome admin init/reset` 和跑着的服务会同时改它）。
//
// 中继的设计前提是「按这台 VPS 已经被人拿下来设计」（docs/DESIGN.md §1），后台没有改变这条：
//
//   - passkey 只存**公钥**，泄露了没用；
//   - SessionKey 是这里唯一的秘密，它能签出一个后台会话 —— 而后台能做的事（出邀请码、删主机）
//     上限是**断网**：冒领一个主机名还得有那个名字的证书，CAA 只认主机自己的 ACME 账户 + dns-01，
//     中继签不出来。所以它和「VPS 被拿下」是同一档后果，没有升级；
//   - 第一次注册 passkey 的一次性令牌只存哈希。
type file struct {
	// Handle 是 WebAuthn 的 user handle：只有一个管理员，所有 passkey 都挂在它名下
	Handle     []byte     `json:"handle"`
	SessionKey []byte     `json:"sessionKey"`
	Keys       []*Passkey `json:"keys"`
	Setup      *setup     `json:"setup,omitempty"`
}

type setup struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
}

// Passkey 是管理员的一把 passkey。Cred 里是公钥和计数器，没有秘密。
type Passkey struct {
	ID       string              `json:"id"`
	Label    string              `json:"label"`
	Created  time.Time           `json:"created"`
	LastUsed time.Time           `json:"lastUsed"`
	Cred     webauthn.Credential `json:"cred"`
}

// SetupTTL：`dialhome admin init` 印出来的链接多久作废。够人从 VPS 终端上抄到手机上点开，
// 短到截图漏出去也来不及用（和邀请码一档）。
const SetupTTL = 30 * time.Minute

// Data 读写 admin.json。
type Data struct{ Store relay.Store }

func (d Data) path() string { return filepath.Join(d.Store.Dir, "admin.json") }

// load 不拿锁，调用方负责。读坏了就报错，**不当成空的**：当成空的下一步就是写回一份空的，
// 把所有 passkey 抹掉（和主机表同一条规矩）。
func (d Data) load() (*file, error) {
	f := &file{}
	b, err := os.ReadFile(d.path())
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, err
	}
	return f, nil
}

func (d Data) save(f *file) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path())
}

// Read 读一份快照。
func (d Data) Read() (*file, error) {
	var f *file
	err := d.Store.Locked(func() (err error) { f, err = d.load(); return })
	return f, err
}

// Update 在锁里读改写。handle / 会话密钥第一次用到时生成。
func (d Data) Update(fn func(*file) error) error {
	return d.Store.Locked(func() error {
		f, err := d.load()
		if err != nil {
			return err
		}
		if len(f.Handle) == 0 {
			f.Handle = randBytes(32)
		}
		if len(f.SessionKey) == 0 {
			f.SessionKey = randBytes(32)
		}
		if err := fn(f); err != nil {
			return err
		}
		return d.save(f)
	})
}

// NewSetup 出一个注册管理员 passkey 的一次性令牌（`dialhome admin init`）。令牌只在这里返回一次。
//
// 已经有 passkey 时照样能出：这就是「换了手机 / 加一台设备」的路，而能跑这条命令的人本来就有
// VPS 的 shell，比后台大得多。
func (d Data) NewSetup() (string, error) {
	tok := hex.EncodeToString(randBytes(16))
	err := d.Update(func(f *file) error {
		f.Setup = &setup{Hash: hashToken(tok), Expires: time.Now().Add(SetupTTL)}
		return nil
	})
	return tok, err
}

// Reset 删掉所有 passkey、换掉会话密钥（所有已登录的会话当场作废）、作废没用掉的令牌。
// 返回删了几把。passkey 丢了 / 怀疑被人登进去过时用。
func (d Data) Reset() (int, error) {
	n := 0
	err := d.Update(func(f *file) error {
		n = len(f.Keys)
		f.Keys = nil
		f.SessionKey = randBytes(32)
		f.Setup = nil
		return nil
	})
	return n, err
}

func (f *file) setupOK(tokHash string, now time.Time) bool {
	return f.Setup != nil && now.Before(f.Setup.Expires) &&
		subtle.ConstantTimeCompare([]byte(f.Setup.Hash), []byte(tokHash)) == 1
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 读不出来：" + err.Error())
	}
	return b
}
