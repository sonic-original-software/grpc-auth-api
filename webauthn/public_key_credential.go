//revive:disable:package-comments
package webauthn

// ParsePublicKeyCredentialType resolves a PublicKeyCredentialType by name.
func ParsePublicKeyCredentialType(name string) PublicKeyCredentialType {
	return parseEnum[PublicKeyCredentialType](name, PublicKeyCredentialType_value)
}

// ParseAttestationConveyancePreference resolves an AttestationConveyancePreference by name.
func ParseAttestationConveyancePreference(name string) AttestationConveyancePreference {
	return parseEnum[AttestationConveyancePreference](name, AttestationConveyancePreference_value)
}

// ParseCoseAlgorithm resolves a CoseAlgorithm by name.
func ParseCoseAlgorithm(name string) CoseAlgorithm {
	return parseEnum[CoseAlgorithm](name, CoseAlgorithm_value)
}
