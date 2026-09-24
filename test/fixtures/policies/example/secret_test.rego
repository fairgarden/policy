package example.secret_test

import rego.v1

import data.example.policy

test_carol_may if policy.authz.allow with input as {"user": "carol"}

test_nobody_gets_the_secret if {
	decision := policy.release with input as {"scopes": ["a", "secret"]}
	decision.scopes == ["a"]
	decision.reasons == {"secret": "Nobody gets the secret."}
}
