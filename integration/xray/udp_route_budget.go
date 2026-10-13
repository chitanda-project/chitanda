package chitanda

import "sync"

// Bound idle receive buffers and goroutines across physical associations.
const maxNativeUDPRoutes = 1024
const maxNativeUDPUserRoutes = 256

var nativeRouteBudget = struct {
	sync.Mutex
	used  int
	users map[string]int
}{users: make(map[string]int)}

func reserveNativeRoute(user string) (func(), bool) {
	nativeRouteBudget.Lock()
	defer nativeRouteBudget.Unlock()
	if nativeRouteBudget.used >= maxNativeUDPRoutes || nativeRouteBudget.users[user] >= maxNativeUDPUserRoutes {
		return nil, false
	}
	nativeRouteBudget.used++
	nativeRouteBudget.users[user]++
	var once sync.Once
	return func() {
		once.Do(func() {
			nativeRouteBudget.Lock()
			defer nativeRouteBudget.Unlock()
			nativeRouteBudget.used--
			nativeRouteBudget.users[user]--
			if nativeRouteBudget.users[user] == 0 {
				delete(nativeRouteBudget.users, user)
			}
		})
	}, true
}
