package policy["com.styra.kubernetes.validating"].rules.rules

import input.attributes.request.http.headers as headers

deny_request[msg] {
	input.attributes.request.http.host == "nginx-service.default.svc.cluster.local"
	msg := "Access to nginx-service is denied."
}

deny_request[msg] {
	input.attributes.destination.namespace == "default"
	input.attributes.destination.service.name == "nginx-service"
	msg := "Access to nginx-service in default namespace is denied."
}

default allow = true

allow {
	not chrome_browser
}

chrome_browser {
	contains(headers["user-agent"], "Mozilla/5.0")
}

block_productpage_v1 {
	input.attributes.destination.service.name == "productpage-v1"
	input.attributes.destination.service.namespace == "default"
	chrome_browser
}
