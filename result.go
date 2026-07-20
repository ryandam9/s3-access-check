package main

// AccessState is the trichotomy a security check must express: a definite
// positive, a definite negative, or "could not determine". Collapsing the third
// case into "not public" is how an audit tool produces dangerous false
// negatives, so every probe result carries one of these.
type AccessState string

const (
	// AccessPublic means an anonymous request succeeded.
	AccessPublic AccessState = "public"
	// AccessNotPublic means an anonymous request was definitively denied or the
	// resource is absent.
	AccessNotPublic AccessState = "not_public"
	// AccessInconclusive means the check could not establish either outcome
	// (redirect loop, throttling, 5xx, timeout, transport error, unexpected
	// status). It must never be reported as "not public".
	AccessInconclusive AccessState = "inconclusive"
)

// Verdict renders a state as a short upper-case label for human output.
func (s AccessState) Verdict() string {
	switch s {
	case AccessPublic:
		return "PUBLIC"
	case AccessNotPublic:
		return "NOT PUBLIC"
	default:
		return "INCONCLUSIVE"
	}
}
