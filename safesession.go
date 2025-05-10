// Package safesession 实现安全登录会话。
//
// 这里的session表示保持登录的session。
package safesession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"
	"unsafe"

	"github.com/mileusna/useragent"
	"github.com/qiulaidongfeng/safesession/codec"
)

// Test 为true将在创建 [Session] 时不获取ip属地。
var Test = false

// Control 管理所有 [Session]。
//
// 零值无效，必须使用 [NewControl] 初始化。
type Control struct {
	// db 是用来保存 [Session] 的数据库。
	db DB
	// sessionMaxAge 设置 [Session] 本身的有效期。
	sessionMaxAge time.Duration
	// sameSite 设置 [Session] 保存到cookie的sameSite属性，
	// 默认为Lex，确保从浏览器搜索结果进入网站时，能够自动登录。
	sameSite http.SameSite
	// aesgcm 用于加密 [Session] 。
	aesgcm cipher.AEAD
	// getIPInfo 获取IP信息。
	getIPInfo func(clientIp string) IPInfo
}

// DB 包含需要的数据库操作。
//
// 从多个goroutine调用里面的字段方法应该是安全的。
type DB struct {
	// Store 存储验证 [Session] 本身有效的必要信息到数据库，
	// 返回false表示ID重复。
	Store func(ID string, CreateTime time.Time) bool
	// Delete 从数据库删除 [Session] 。
	Delete func(ID string)
	// Exist 查询是否有指定的 [Session] 。
	Exist func(ID string) bool
	// Valid 验证 [Session] 表示的用户登录状态有效。
	Valid func(UserName string, SessionID string) error
}

// Session 表示一个登录会话。
type Session struct {
	// ID 对每个登录会话是唯一的。
	ID string `gorm:"primaryKey;type:char(64)"`
	// CreateTime 是创建登录会话的时间。
	CreateTime time.Time
	// Ip 是创建登录会话时的ip信息。
	Ip IPInfo `json:"-" gorm:"-:all"`
	// CSRF_TOKEN 用来防范跨站请求伪造攻击。
	CSRF_TOKEN string
	// 下列字段是创建登录会话时的客户端设备信息，
	// 和ip信息以及CSRF_TOKEN一起保存在客户浏览器，不在服务器保存。
	Os, OsVersion string `json:"-" gorm:"-:all"`
	Name          string `json:"-" gorm:"-:all"`
	Device        string `json:"-" gorm:"-:all"`
	Broswer       string `json:"-" gorm:"-:all"`
}

// NewControl 创建一个 [Control] 。
// 数据库应自行实现清除过期的 [Session] ·。
func NewControl(aeskey [32]byte, sessionMaxAge time.Duration, sameSite http.SameSite, getIPInfo func(clientIp string) IPInfo, Db DB) *Control {
	var c = new(Control)
	b, err := aes.NewCipher(aeskey[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(b)
	if err != nil {
		panic(err)
	}
	c.aesgcm = gcm
	if c.sameSite != 0 {
		c.sameSite = sameSite
	} else {
		c.sameSite = http.SameSiteLaxMode
	}
	c.sessionMaxAge = sessionMaxAge
	c.getIPInfo = getIPInfo
	c.db = Db
	return c
}

// NewSession 创建一个 [Session] ，保证ID不重复。
// 从多个goroutine调用是安全的。
func (c *Control) NewSession(clientIP, userAgent, UserName string) Session {
	s := c.newSession(clientIP, userAgent, UserName)
	for {
		// 在ID不重复时返回。
		if c.db.Store(s.ID, s.CreateTime) {
			return s
		}
		s.ID = genID()
	}
}

// genID 随机生成一个ID。
func genID() string {
	var b [32]byte
	var err error
	_, err = rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// newSession 创建一个 [Session] ， 随机生成ID，不保证ID不重复。
func (c *Control) newSession(clientIP, userAgent, UserName string) Session {
	s := Session{}
	s.ID = genID()
	s.CreateTime = time.Now()
	s.Name = UserName
	if !Test { // 不要在测试时获取ip属地。
		s.Ip = c.getIPInfo(clientIP)
	}
	u := useragent.Parse(userAgent)
	s.Device = u.Device
	s.Os = u.OS
	s.OsVersion = u.OSVersion
	s.Broswer = u.Name
	return s
}

// decode 将cookie值解码为 [Session] 。
func (s *Session) decode(v string) bool {
	return codec.Decode(s, v)
}

// encode 将 [Session] 编码为字符串。
func (s *Session) encode() string {
	return codec.Encode(s)
}

var LoginExpired = errors.New("登录已过期，请重新登录")
var RegionErr = errors.New("IP属地在两次登录时不在同一个地区，请重新登录")
var mayStolen = errors.New("登录疑似存在风险，请重新登录")

// Check 检查用户的 [Session] 是否有效。
// 从多个goroutine调用是安全的。
func (c *Control) Check(clientIP, userAgent string, s *Session) (bool, error) {
	// 有些浏览器会发送刚过期的cookie,
	// 所以检查登录会话本身是否已经过期。
	if s.CreateTime.Sub(time.Now()) >= c.sessionMaxAge {
		c.db.Delete(s.ID)
		return false, LoginExpired
	}
	// 如果是测试或创建登录会话时没有获得ip属地，
	// 就不要检查ip属地在创建登录会话和现在使用登录会话时是否一致。
	if !Test && s.Ip.Country != "" {
		userIp := c.getIPInfo(clientIP)
		if userIp != s.Ip && userIp.Country != "" {
			c.db.Delete(s.ID)
			return false, RegionErr
		}
	}
	// 检查设备信息，
	// 在创建登录会话和现在使用登录会话时是否一致。
	u := useragent.Parse(userAgent)
	if u.OS != s.Os || u.Device != s.Device || u.OSVersion != s.OsVersion || u.Name != s.Broswer {
		c.db.Delete(s.ID)
		return false, mayStolen
	}
	// 检查登录会话表示的用户登录状态。
	// Note: 可能因为只允许在一台设备登录等原因，
	// 即使有多个登录会话本身有效，但只有最近一个创建的登录会话能成功登录，
	// 所以还要检查这个登录会话能否成功登录。
	if err := c.db.Valid(s.Name, s.ID); err != nil {
		c.db.Delete(s.ID)
		return false, err
	}
	return true, nil
}

// IPInfo 是ip信息。
type IPInfo struct {
	// Country 是ip属地。
	// 正确命名应该是Region，为了向后兼容，所以不修改。
	Country string `json:"country"`
}

// CheckLogined 检查是否已经登录。
// 从多个goroutine调用是安全的。
func (c *Control) CheckLogined(clientIP, userAgent string, cookie *http.Cookie) (bool, error, Session) {
	ok, se := c.decodeSession(cookie.Value)
	if ok && c.db.Exist(se.ID) {
		ok, err := c.Check(clientIP, userAgent, &se)
		return ok, err, se
	}
	return false, nil, Session{}
}

// SetSession 设置已创建的登录会话。
// 只能在https时使用。
// 只要每次调用的w不同，从多个goroutine调用是安全的。
func (c *Control) SetSession(se *Session, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    c.encodeSession(se),
		Path:     "/",
		SameSite: c.sameSite,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   int(c.sessionMaxAge.Seconds()),
	})
}

// encodeSession 编码 [Session] 为cookie值。
func (c *Control) encodeSession(se *Session) string {
	// 编码为字符串。
	v := se.encode()
	// 加密。
	v = c.encrypt(v)
	// 转义为能安全地放置在URL查询的文本。
	return url.QueryEscape(v)
}

// decodeSession 从cookie值中解码 [Session] 。
func (c *Control) decodeSession(v string) (bool, Session) {
	// 恢复成密文。
	v, err := url.QueryUnescape(v)
	if err != nil {
		return false, Session{}
	}
	// 解密。
	s := c.decrypt(v)
	var se Session
	// 解码。
	ok := se.decode(s)
	return ok, se
}

// encrypt 使用aes256-gcm进行加密。
func (c *Control) encrypt(s string) string {
	b := c.aesgcm.Seal(nil, nil, unsafe.Slice(unsafe.StringData(s), len(s)), nil)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// decrypt 使用aes256-gcm进行解密。
func (c *Control) decrypt(s string) string {
	b, err := c.aesgcm.Open(nil, nil, unsafe.Slice(unsafe.StringData(s), len(s)), nil)
	if err != nil {
		panic(err)
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
