package fairgarden.bylaws_test

import data.fairgarden.events
import data.fairgarden.members.governance
import rego.v1

signoff(name, voting) := {"by": {"name": name, "voting": voting}}

test_an_event_needs_two_voting_members if {
	one := events.approve with input as {"event": {"id": "e1"}, "signoffs": [signoff("ada", true), signoff("bo", false)]}
	not one.allow
	one.reasons == {"signoffs": "1 of the 2 voting members it needs have signed it off."}

	events.approve.allow with input as {"event": {"id": "e1"}, "signoffs": [signoff("ada", true), signoff("cy", true)]}
}

test_signing_twice_counts_once if {
	not events.approve.allow with input as {"event": {"id": "e1"}, "signoffs": [signoff("ada", true), signoff("ada", true)]}
}

test_voting_takes_25_volunteer_hours if {
	new := governance.voting with input as {"member": {"name": "ada", "status": "active", "volunteer_hours": 20}}
	new.reasons == {"hours": "5 more volunteer hours, to vote."}

	governance.voting.allow with input as {"member": {"name": "ada", "status": "active", "volunteer_hours": 25}}
}

test_removal_takes_half_the_voters if {
	short := governance.remove with input as {"member": {"name": "x"}, "votes": {"for": 4, "against": 1}, "voters": 10}
	short.reasons == {"votes": "1 more votes for it: half the voting members must agree."}

	governance.remove.allow with input as {"member": {"name": "x"}, "votes": {"for": 5, "against": 5}, "voters": 10}
}

test_an_officer_needs_a_majority if {
	tied := governance.appoint with input as {"office": "secretary", "candidate": {"name": "ada"}, "election": {"votes": {"ada": 5, "bo": 5}}}
	tied.reasons == {"majority": "ada won 5 of 10 votes cast: not a majority."}

	governance.appoint.allow with input as {"office": "secretary", "candidate": {"name": "ada"}, "election": {"votes": {"ada": 6, "bo": 4}}}
	not governance.appoint.allow with input as {"office": "treasurer", "candidate": {"name": "ada"}, "election": {"votes": {"ada": 6}}}
}
