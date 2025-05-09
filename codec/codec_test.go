package codec_test

import (
	"net/url"
	"reflect"
	"testing"
	"time"

	. "github.com/qiulaidongfeng/safesession"
	. "github.com/qiulaidongfeng/safesession/codec"
)

func TestCodeSession(t *testing.T) {
	s := Session{
		ID:         "19063",
		Ip:         IPInfo{Country: "c"},
		Os:         "k",
		CreateTime: time.Now(),
	}
	result := Session{}
	c := Encode(s)
	t.Log(c)
	Decode(&result, c)
	if !reflect.DeepEqual(s, result) && !s.CreateTime.Equal(result.CreateTime) {
		t.Fatalf("%+v != %+v", s, result)
	}
}

func TestCodeSessionCookie(t *testing.T) {
	s := Session{
		ID:         "19063",
		Ip:         IPInfo{Country: "c b"},
		Os:         "k",
		CreateTime: time.Now(),
	}
	result := Session{}
	c := Encode(s)
	t.Log(c)
	c = url.QueryEscape(c)
	t.Log(c)
	c, err := url.QueryUnescape(c)
	if err != nil {
		panic(err)
	}
	Decode(&result, c)
	if !reflect.DeepEqual(s, result) && !s.CreateTime.Equal(result.CreateTime) {
		t.Fatalf("%+v != %+v", s, result)
	}
}
