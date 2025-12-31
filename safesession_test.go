package safesession

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var delete_num = 0

var c = func() *Control {
	m := make(map[string]any)
	db := DB{
		Store: func(ID string, CreateTime time.Time) bool {
			if _, ok := m[ID]; ok {
				return false
			}
			m[ID] = CreateTime
			return true
		},
		Delete: func(ID string) {
			delete_num++
			delete(m, ID)
		},
		Exist: func(ID string) bool {
			_, ok := m[ID]
			return ok
		},
		Valid: func(UserName string, SessionID string) error {
			if UserName == "ok" || SessionID == "ok" {
				return nil
			}
			return testErr
		},
	}
	c := NewControl(func(s string) string { return s }, func(s string) string { return s }, 12*time.Hour, 0, func(clientIp string) IPInfo {
		c := "CN"
		if clientIp == "192.168.0.2" {
			c = "US"
		}
		return IPInfo{Country: c}
	}, db)
	return c
}()

var testErr = errors.New("test")
var user_agent = "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Mobile Safari/537.36"

func TestAll(t *testing.T) {
	s := c.NewSession("192.168.0.1", user_agent, "ok")
	if s.Ip.Country != "CN" {
		t.Fatalf("got %s, want CN", s.Ip.Country)
	}
	if s.Os != "Android" {
		t.Fatalf("got %s, want Android", s.Os)
	}
	if s.OsVersion != "6.0" {
		t.Fatalf("got %s, want 6.0", s.OsVersion)
	}
	if s.Name != "ok" {
		t.Fatalf("got %s, want ok", s.Name)
	}
	if s.Device != "Nexus 5" {
		t.Fatalf("got %s, want Nexus 5", s.Device)
	}
	if s.Broswer != "Chrome" {
		t.Fatalf("got %s, want Chrome", s.Broswer)
	}
	w := httptest.NewRecorder()
	c.SetSession(&s, w)
	cs := w.Result().Cookies()
	if cs[0].MaxAge != 43200 {
		t.Fatalf("got %d, want 43200", cs[0].MaxAge)
	}
	if !cs[0].HttpOnly {
		t.Fatalf("should HttpOnly")
	}
	if !cs[0].Secure {
		t.Fatalf("should Secure")
	}
	if cs[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("should Lax mode")
	}
	if cs[0].Name != "session" {
		t.Fatalf("got %s, want session", cs[0].Name)
	}
	if logined, err, _ := c.CheckLogined("192.168.0.1", user_agent, cs[0]); !logined || err != nil {
		t.Log(logined)
		t.Fatal(err)
	}
	ok, s2 := c.decodeSession(cs[0].Value)
	if !ok {
		t.Fatalf("should success")
	}
	if s != s2 && !s.CreateTime.Equal(s2.CreateTime) {
		t.Fatalf("%s\n%s\n", s.encode(), s2.encode())
	}
	if _, err := c.Check("192.168.0.2", user_agent, &s2); err != RegionErr {
		t.Fatal(err)
	}
	if _, err := c.Check("192.168.0.1", "", &s2); err != MayStolen {
		t.Fatal(err)
	}
	s2.Name = "testErr"
	if _, err := c.Check("192.168.0.1", user_agent, &s2); err != testErr {
		t.Fatal(err)
	}
	s2.ID = "ok"
	if _, err := c.Check("192.168.0.1", user_agent, &s2); err != nil {
		t.Fatal(err)
	}
	if delete_num != 3 {
		t.Log(delete_num)
		t.Fatalf("Delete should be called three times")
	}
}
