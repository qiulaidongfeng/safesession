// Package codec 实现编解码。
//
// 只支持字符串和time.Time类型。
package codec

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unsafe"
)

/*
编码格式为

value1 value2 ......

time.Time 编码为它的GobEncode()结果

考虑到被编码值可能包含空格，所以编码后的分隔从空格改为byte(0)
*/

const sep = string(sepb)
const sepb = byte(0)

// Encode 将值编码为字符串。
func Encode(v any) string {
	r := reflect.ValueOf(v)
	if r.Kind() == reflect.Ptr {
		r = r.Elem()
	}
	var buf strings.Builder
	encodeBuf(r, &buf)
	return buf.String()
}

func encodeBuf(r reflect.Value, buf *strings.Builder) {
	for i := 0; i < r.NumField(); i++ {
		f := r.Field(i)
		switch f.Kind() {
		case reflect.String:
			buf.WriteString(f.String())
			buf.WriteString(sep)
		case reflect.Struct:
			if r.Type().Field(i).Type == timetime {
				b, err := f.Interface().(time.Time).GobEncode()
				if err != nil {
					panic(err)
				}
				buf.WriteString(base64.StdEncoding.EncodeToString(b))
				buf.WriteString(sep)
			} else {
				encodeBuf(f, buf)
			}
		default:
			panic(fmt.Errorf("未知的类型 %s", r.Type()))
		}
	}
}

// Decode 将字符串解码为指定类型的值。
// 如果解码失败，返回false。
func Decode[T any](v *T, code string) (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			ok = false
		}
	}()
	r := reflect.ValueOf(v).Elem()
	decodeStruct(r, code)
	return true
}

func decodeStruct(r reflect.Value, code string) string {
	for i := 0; i < r.NumField(); i++ {
		f := r.Field(i)
		code = decodeField(f, code)
	}
	return code
}

func decodeField(r reflect.Value, code string) string {
	switch r.Kind() {
	case reflect.String:
		var v string
		code, v = getValue(code)
		r.SetString(v)
	case reflect.Struct:
		if r.Type() == timetime {
			var v string
			code, v = getValue(code)
			t := time.Time{}
			vb, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				panic(err)
			}
			v = unsafe.String(&vb[0], len(vb))
			err = t.GobDecode(unsafe.Slice(unsafe.StringData(v), len(v)))
			if err != nil {
				panic(err)
			}
			r.Set(reflect.ValueOf(t))
			return code
		}
		code = decodeStruct(r, code)
	default:
		panic(fmt.Errorf("未知的类型 %s", r.Type()))
	}
	return code
}

// getValue 获取一个值，并返回剩下未解码的值。
func getValue(code string) (string, string) {
	// 获取值
	var v string
	for i := range code {
		if code[i] == sepb {
			v = code[:i]
			code = code[i+1:]
			break
		}
	}
	return code, v
}

var timetime = reflect.TypeOf(time.Time{})
