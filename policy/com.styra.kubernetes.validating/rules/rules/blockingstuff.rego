package istio.authz

# Define the main rule for the policy
deny_request[msg] {
  input.attributes.request.http.path == "/productpage"
  input.attributes.source.workload.name != "productpage-v1"
  msg := "Access to productpage-v1 is denied."
}

# Deny all requests to the productpage-v1 service in the default namespace
deny_request[msg] {
  input.attributes.destination.namespace == "default"
  input.attributes.destination.workload.name == "productpage-v1"
  msg := "Access to productpage-v1 in default namespace is denied."
}
