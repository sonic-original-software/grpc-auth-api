//revive:disable:package-comments
package webauthn

// parseEnum resolves name against a generated enum's value map.
// An unknown name yields the enum's unspecified value.
func parseEnum[T ~int32](name string, values map[string]int32) T {
	return T(values[name])
}
