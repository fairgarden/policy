# What an events service would ship: the question it asks before an event is
# announced, and a place for the organization's rules. Not a real service —
# the base the bylaws in ../organization build on.
package fairgarden.events

import rego.v1

# METADATA
# title: Which events are announced
# description: An event is announced once nothing the organization requires is missing.
# entrypoint: true
approve := {"allow": count(unmet) == 0, "reasons": unmet}

# input.event     {id, title}
# input.signoffs  [{by: {name, voting}}]  who has approved it; `voting` is
#                 the members service's `voting` decision about them

# Nothing, until an organization adds to it.
unmet[requirement] := reason if {
	false
	requirement := ""
	reason := ""
}
