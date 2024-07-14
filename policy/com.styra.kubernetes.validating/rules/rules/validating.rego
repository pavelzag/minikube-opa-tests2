package policy["com.styra.kubernetes.validating"].rules.rules

deny_request[msg] {
  input.attributes.request.http.path == "/productpage"
  input.attributes.source.workload.name != "productpage-v1"
  msg := "Access to productpage-v1 is denied."
}

deny_request[msg] {
  input.attributes.destination.namespace == "default"
  input.attributes.destination.workload.name == "productpage-v1"
  msg := "Access to productpage-v1 in default namespace is denied."
}
