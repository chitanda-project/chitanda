package server

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

const MaxUDPTargets = 1024
const MaxUserUDPTargets = 256

var udpTargetsBudget = struct {
	sync.Mutex
	used  int
	users map[string]int
}{users: make(map[string]int)}

// UDPResourceIdentity shares capacity across transports/listeners using the
// same credential, without exporting the credential itself.
func UDPResourceIdentity(psk []byte) string { return fmt.Sprintf("%x", sha256.Sum256(psk)) }

// ReserveUDPTarget includes sockets still being created. The lease must be
// released on every failure, cancellation and target close; release is idempotent.
func ReserveUDPTarget(identity string) (func(), bool) {
	udpTargetsBudget.Lock()
	defer udpTargetsBudget.Unlock()
	if udpTargetsBudget.used >= MaxUDPTargets || udpTargetsBudget.users[identity] >= MaxUserUDPTargets {
		return nil, false
	}
	udpTargetsBudget.used++
	udpTargetsBudget.users[identity]++
	var once sync.Once
	return func() {
		once.Do(func() {
			udpTargetsBudget.Lock()
			defer udpTargetsBudget.Unlock()
			udpTargetsBudget.used--
			udpTargetsBudget.users[identity]--
			if udpTargetsBudget.users[identity] == 0 {
				delete(udpTargetsBudget.users, identity)
			}
		})
	}, true
}
