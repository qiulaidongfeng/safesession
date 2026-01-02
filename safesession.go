// Package safesession 实现安全登录会话。
//
// 这里的session表示保持登录的session。
//
// AES-256-GCM的加解密函数可以从https://github.com/qiulaidongfeng/key获取
package safesession

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
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
	// encrypt,decrypt 加解密 [Session]
	encrypt, decrypt func(string) string
	// getIPInfo 获取IP信息。
	getIPInfo func(clientIp string) IPInfo
	// CheckIPInfo 允许调用者覆盖默认检查IP信息是否相差过大逻辑。
	CheckIPInfo func(old, new IPInfo) bool
	// SessionCookieName 允许调用者设置写入响应的Cookie name
	SessionCookieName func(s *Session) string
	// CheckCallBack 在被盗检查不通过时允许调用者进行二次验证
	CheckCallBack func(s *Session, clientIP, userAgent string, p PostInfo) bool
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
	// CreateTime 是上一次登录的时间。
	// 应该命名为LastLoginTime，为了不在生产环境修改数据库表，
	// 所以不改名。
	CreateTime time.Time
	// Ip 是上一次登录的ip信息。
	Ip IPInfo `json:"-" gorm:"-:all"`
	// Gps 是上一次登录的gps信息。
	Gps GpsInfo `json:"-" gorm:"-:all"`
	// CSRF_TOKEN 用来防范跨站请求伪造攻击。
	// 调用者设置它。
	CSRF_TOKEN string `json:"-" gorm:"-:all"`
	// 下列字段是创建登录会话时的客户端设备信息，
	// 和ip信息以及CSRF_TOKEN一起保存在客户浏览器，不在服务器保存。
	Os, OsVersion string `json:"-" gorm:"-:all"`
	// Name 是用来登录的用户的唯一身份表示。
	Name string `json:"-" gorm:"-:all"`
	// Device 是浏览器指纹或设备指纹。
	Device string `json:"-" gorm:"-:all"`
	// Broswer 是浏览器名
	// Browser是正确拼写，为了不在生产环境修改数据库表，
	// 所以不改名。
	// 在非浏览器环境运行时，设置为user-agent提取到的应用名。
	Broswer string `json:"-" gorm:"-:all"`
	Screen  Screen `json:"-" gorm:"-:all"`
	// PNum 是逻辑处理器数量，
	// 通常使用navigator.hardwareConcurrency获取。
	PNum int64 `json:"-" gorm:"-:all"`
}

// IPInfo 是ip信息。
type IPInfo struct {
	Country, Region, City string
	ISP                   string
	Longitude, Latitude   float64
	AS                    int64
}

// GpsInfo 是gps信息。
type GpsInfo struct {
	Longitude, Latitude float64
}

// Screen 是屏幕信息。
type Screen struct {
	Width, Height int64
}

// NewControl 创建一个 [Control] 。
// 数据库应自行实现清除过期的 [Session] ·。
func NewControl(encrypt, decrypt func(string) string, sessionMaxAge time.Duration, sameSite http.SameSite,
	getIPInfo func(clientIp string) IPInfo,
	Db DB) *Control {
	var c = new(Control)
	c.encrypt, c.decrypt = encrypt, decrypt
	if sameSite != 0 {
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
	s.Os = u.OS
	s.OsVersion = u.OSVersion
	s.Broswer = u.Name
	s.Gps.Latitude = math.MaxFloat64
	s.Gps.Longitude = math.MaxFloat64
	s.PNum = -1
	s.Screen.Width = -1
	s.Screen.Height = -1
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

type PostInfo struct {
	Gps    GpsInfo
	Screen Screen
	PNum   int64
	Device string
}

// SetPostInfo 设置应该由POST请求提供的验证信息
// 注意int类型的字段，未能获取时应该设置为-1，float64则为 [math.MaxFloat64].
func (s *Session) SetPostInfo(i PostInfo) {
	s.PNum = i.PNum
	s.Device = i.Device
	s.Screen = i.Screen
	s.Gps = i.Gps
}

var LoginExpired = errors.New("登录已过期，请重新登录")
var RegionErr = errors.New("IP属地在两次登录时不在同一个地区，请重新登录")
var MayStolen = errors.New("登录疑似存在风险，请重新登录")

// Check 检查用户的 [Session] 是否未被盗且未登录失效。
// 从多个goroutine调用是安全的。
// 假设已验证Session ID未过期。
func (c *Control) Check(clientIP, userAgent string, s *Session, ps ...PostInfo) (pass bool, err error) {
	// 有些浏览器会发送刚过期的cookie,
	// 所以检查登录会话本身是否已经过期。
	if time.Since(s.CreateTime) >= c.sessionMaxAge {
		c.db.Delete(s.ID)
		return false, LoginExpired
	}
	var p PostInfo
	if len(ps) != 0 {
		p = ps[0]
	} else {
		p.PNum = -1
		p.Gps.Latitude = math.MaxFloat64
		p.Gps.Longitude = math.MaxFloat64
		p.Screen.Height = -1
		p.Screen.Width = -1
	}
	// 高灵敏度特征检查
	u := useragent.Parse(userAgent)
	if u.OS != s.Os || u.Name != s.Broswer {
		if c.CheckCallBack != nil && c.CheckCallBack(s, clientIP, userAgent, p) {
			return true, nil
		}
		c.db.Delete(s.ID)
		return false, MayStolen
	}

	// 高特异性特征检查
	device_ok := false
	if s.Device != "" && s.Device == p.Device {
		device_ok = true
	}
	fail := 0

	// 如果是测试
	// 就不要检查ip信息在创建登录会话和现在使用登录会话时是否一致。
	if !Test {
		userIp := c.getIPInfo(clientIP)
		if c.CheckIPInfo != nil {
			if !c.CheckIPInfo(s.Ip, userIp) {
				fail++
			}
		} else {
			if s.Ip.ISP != "" && s.Ip.ISP != userIp.ISP {
				fail++
			}
			if s.Ip.AS != -1 && s.Ip.AS != userIp.AS {
				fail++
			}
			if !s.checkIp(userIp, &err) {
				fail++
			}
		}
	}

	if s.PNum != -1 && s.PNum != p.PNum {
		fail++
	}
	if s.OsVersion != "" && s.OsVersion != u.OSVersion {
		fail++
	}
	if s.Screen.Height != -1 && s.Screen.Height != p.Screen.Height {
		fail++
	}
	if s.Screen.Width != -1 && s.Screen.Width != p.Screen.Width {
		fail++
	}

	if !device_ok && fail >= 1 {
		if c.CheckCallBack != nil && c.CheckCallBack(s, clientIP, userAgent, p) {
			return true, nil
		}
		c.db.Delete(s.ID)
		if err == nil {
			err = MayStolen
		}
		return false, err
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

func (s *Session) checkIp(newInfo IPInfo, e *error) bool {
	if s.Ip.Country != "" && s.Ip.Country != newInfo.Country {
		*e = RegionErr
		return false
	}
	if s.Ip.Region != "" && s.Ip.Region != newInfo.Region {
		*e = RegionErr
		return false
	}
	if Distance(s.Ip.Latitude, s.Ip.Longitude, newInfo.Latitude, newInfo.Longitude) > 50 {
		*e = RegionErr
		return false
	}
	return true
}

// CheckLogined 检查是否已经登录。
// 从多个goroutine调用是安全的。
// 如果err!=nil,调用者应该删除cookie（响应MaxAge<0）。
func (c *Control) CheckLogined(clientIP, userAgent string, cookie *http.Cookie, p ...PostInfo) (bool, error, Session) {
	ok, se := c.decodeSession(cookie.Value)
	if ok && c.db.Exist(se.ID) {
		ok, err := c.Check(clientIP, userAgent, &se, p...)
		return ok, err, se
	}
	return false, nil, Session{}
}

// SetSession 设置已创建的登录会话。
// 只能在https时使用。
// 只要每次调用的w不同，从多个goroutine调用是安全的。
func (c *Control) SetSession(se *Session, w http.ResponseWriter) {
	name := "session"
	if c.SessionCookieName != nil {
		name = c.SessionCookieName(se)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
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
	return base32.StdEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(v), len(v)))
}

// decodeSession 从cookie值中解码 [Session] 。
func (c *Control) decodeSession(v string) (bool, Session) {
	// 恢复成密文。
	b, err := base32.StdEncoding.DecodeString(v)
	if err != nil {
		return false, Session{}
	}
	v = unsafe.String(unsafe.SliceData(b), len(b))
	// 解密。
	s := c.decrypt(v)
	var se Session
	if s == "" {
		return false, se
	}
	// 解码。
	ok := se.decode(s)
	return ok, se
}

const earthRadiusKm = 6371 // 地球半径，单位：公里

// haversin calculates the haversine of an angle.
func haversin(theta float64) float64 {
	return math.Pow(math.Sin(theta/2), 2)
}

// 这个函数根据两点所在的纬度与经度（以十进制度为单位）来计算它们之间的距离，返回的结果以公里为单位。
// 使用Haversine 公式
func Distance(lat1, lon1, lat2, lon2 float64) float64 {
	// 将角度从度数转换为弧度
	lat1Rad := lat1 * math.Pi / 180
	lon1Rad := lon1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	lon2Rad := lon2 * math.Pi / 180

	// 计算纬度和经度的差值
	dLat := lat2Rad - lat1Rad
	dLon := lon2Rad - lon1Rad

	// 应用 Haversine 公式
	a := haversin(dLat) + math.Cos(lat1Rad)*math.Cos(lat2Rad)*haversin(dLon)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	// 计算距离
	distance := earthRadiusKm * c
	return distance
}
