package example.policy

import rego.v1

withheld["secret"] := "Nobody gets the secret." if "secret" in input.scopes
