package fairgarden.members.governance

import rego.v1

bylaws := data.fairgarden.bylaws

# Article III §1: a member votes once they have given 25 volunteer hours.
unmet_voting["hours"] := sprintf("%d more volunteer hours, to vote.", [bylaws.voting_hours - hours]) if {
	hours := object.get(input.member, "volunteer_hours", 0)
	hours < bylaws.voting_hours
}

# Article III §2: and while their membership is active.
unmet_voting["status"] := "Only active members vote." if input.member.status != "active"

# Article VII §1: a member is removed only when half the members who may vote agree.
unmet_removal["votes"] := sprintf("%d more votes for it: half the voting members must agree.", [needed - input.votes.for]) if {
	needed := ceil(input.voters * bylaws.removal)
	input.votes.for < needed
}

# Article VI §1: officers are elected, by a majority of the votes cast.
unmet_appointment["majority"] := sprintf("%s won %d of %d votes cast: not a majority.", [input.candidate.name, won, cast]) if {
	bylaws.offices[input.office].elected
	won := object.get(input.election.votes, input.candidate.name, 0)
	cast := sum([count | some count in input.election.votes])
	won * 2 <= cast
}

unmet_appointment["office"] := sprintf("The bylaws have no office of %s.", [input.office]) if {
	not bylaws.offices[input.office]
}
