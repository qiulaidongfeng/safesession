package codec_test

import (
	"net/url"
	"reflect"
	"strings"
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

func FuzzCodec(f *testing.F) {
	f.Add("1", time.Now().UnixMilli(), "CN", "Shanghai", "", "China Unicom", 10.0, 20.0, int64(2345), 10.2, 30.4, "ddxefe", "Win", "10", "user", "Edge", "Edge", int64(1920), int64(1280), int64(8))
	f.Fuzz(func(t *testing.T, ID string,
		CreateTime int64,
		Country, Region, City string,
		ISP string,
		Longitude, Latitude float64,
		AS int64,
		Longitude2, Latitude2 float64,
		CSRF_TOKEN string,
		Os, OsVersion string,
		Name string,
		Device string,
		Broswer string,
		Width, Height int64,
		PNum int64) {
		s := Session{
			ID:         ID,
			CreateTime: time.UnixMilli(CreateTime),
			Ip:         IPInfo{Country: Country, Region: Region, City: City, ISP: ISP, Longitude: Longitude, Latitude: Latitude},
			Gps:        GpsInfo{Longitude: Longitude2, Latitude: Latitude2},
			CSRF_TOKEN: CSRF_TOKEN,
			Os:         Os,
			OsVersion:  OsVersion,
			Name:       Name,
			Device:     Device,
			Screen:     Screen{Width: Width, Height: Height},
			PNum:       PNum,
		}
		v := reflect.ValueOf(&s)
		checkStruct(v.Elem())
		c := Encode(s)
		var s2 = new(Session)
		if !Decode(s2, c) {
			t.Fail()
			t.Logf("%+v", c)
		}
		if !reflect.DeepEqual(s, *s2) && !s.CreateTime.Equal(s2.CreateTime) {
			t.Fatalf("%+v != %+v", s, *s2)
		}
	})
}

func checkStruct(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.String {
			s := f.String()
			s = strings.ReplaceAll(s, "\x00", "")
			f.SetString(s)
		}
		if f.Kind() == reflect.Struct {
			checkStruct(f)
		}
	}
}
