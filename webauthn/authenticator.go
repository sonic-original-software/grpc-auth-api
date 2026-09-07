//revive:disable:package-comments
package webauthn

// ParseAuthenticatorAttachment resolves an AuthenticatorAttachment by name.
func ParseAuthenticatorAttachment(name string) AuthenticatorAttachment {
	return parseEnum[AuthenticatorAttachment](name, AuthenticatorAttachment_value)
}

// ParseResidentKeyRequirement resolves a ResidentKeyRequirement by name.
func ParseResidentKeyRequirement(name string) ResidentKeyRequirement {
	return parseEnum[ResidentKeyRequirement](name, ResidentKeyRequirement_value)
}

// ParseUserVerificationRequirement resolves a UserVerificationRequirement by name.
func ParseUserVerificationRequirement(name string) UserVerificationRequirement {
	return parseEnum[UserVerificationRequirement](name, UserVerificationRequirement_value)
}
