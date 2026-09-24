# METADATA
# title: The example service
# description: What the example service may do, and for whom.
# related_resources:
#   - ref: https://example.org/club/bylaws
#     description: The club's bylaws
package example.policy

import rego.v1

# METADATA
# title: Who may act
# description: Only the people the club allows.
# related_resources:
#   - ref: https://example.org/club/bylaws#article-2
#     description: Bylaws, Article II
# entrypoint: true
authz := {"allow": input.user in data.example.settings.allowed}

# METADATA
# title: What is shared
# description: Everything asked for, except what is withheld.
# entrypoint: true
release := {
	"scopes": [scope | some scope in input.scopes; not scope in object.keys(withheld)],
	"reasons": withheld,
}

withheld[scope] := reason if {
	some scope, reason in data.example.settings.withhold
	scope in input.scopes
}
