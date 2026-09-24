# What a members service that runs the organization's governance would ship:
# the questions it asks about voting, removing members and filling offices.
# Not members' own rules — the base the bylaws in ../organization build on.
package fairgarden.members.governance

import rego.v1

# METADATA
# title: Who may vote
# entrypoint: true
voting := {"allow": count(unmet_voting) == 0, "reasons": unmet_voting}

# input.member  {name, status, since, volunteer_hours}

# METADATA
# title: Removing a member
# entrypoint: true
remove := {"allow": count(unmet_removal) == 0, "reasons": unmet_removal}

# input.member  {name}           who would be removed
# input.votes   {for, against}   the vote on it
# input.voters  how many members may vote

# METADATA
# title: Filling an office
# entrypoint: true
appoint := {"allow": count(unmet_appointment) == 0, "reasons": unmet_appointment}

# input.office     "secretary", say
# input.candidate  {name}
# input.election   {votes: {<name>: <count>}}  every candidate's votes

# Nothing, until an organization adds to them.
unmet_voting[requirement] := reason if {
	false
	requirement := ""
	reason := ""
}

unmet_removal[requirement] := reason if {
	false
	requirement := ""
	reason := ""
}

unmet_appointment[requirement] := reason if {
	false
	requirement := ""
	reason := ""
}
