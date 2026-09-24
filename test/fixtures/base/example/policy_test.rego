package example.policy_test

import rego.v1

import data.example.policy

test_alice_may if policy.authz.allow with input as {"user": "alice"}

test_carol_may_not if not policy.authz.allow with input as {"user": "carol"}
