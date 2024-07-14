package policy["com.styra.kubernetes.validating"].rules.rules

deny_request[msg] {
  input.attributes.request.http.host == "nginx-service.default.svc.cluster.local"
  msg := "Access to nginx-service is denied."
}

deny_request[msg] {
  input.attributes.destination.namespace == "default"
  input.attributes.destination.service.name == "nginx-service"
  msg := "Access to nginx-service in default namespace is denied."
}