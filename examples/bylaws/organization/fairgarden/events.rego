# Article V §2: an event is announced once two voting members have signed it off.
package fairgarden.events

import rego.v1

bylaws := data.fairgarden.bylaws

voting_signoffs := {signoff.by.name | some signoff in input.signoffs; signoff.by.voting}

unmet["signoffs"] := sprintf("%d of the %d voting members it needs have signed it off.", [count(voting_signoffs), bylaws.signoffs]) if {
	count(voting_signoffs) < bylaws.signoffs
}
