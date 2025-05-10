//go:build goexperiment.synctest

package safesession

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestExpire(t *testing.T) {
	synctest.Run(func() {
		s := c.NewSession("192.168.0.1", user_agent, "ok")
		time.Sleep(12*time.Hour - time.Second)
		synctest.Wait()
		if _, err := c.Check("192.168.0.1", user_agent, &s); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if _, err := c.Check("192.168.0.1", user_agent, &s); err != LoginExpired {
			t.Fatal(err)
		}
	})
}
