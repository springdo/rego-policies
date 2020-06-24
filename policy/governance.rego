package main

# Rego Policy to validate a template which creates a ProjectRequest or Namespace also 
# adds "ResourceQuota" and "LimitRange" to limit memory consumption
# https://learnk8s.io/production-best-practices#governance

warn[msg] {
  matchers := ["ResourceQuota", "LimitRange"]
  input.kind == "Template" 
  input.objects[_].kind == "ProjectRequest"
  kinds := input.objects[_].kind
  missing_limit_range(kinds)
  missing_quoatas(kinds)
  msg := sprintf("Found a ProjectRequest but no corresponding %s", [matchers])
}


warn[msg] {
  matchers := ["ResourceQuota", "LimitRange"]
  input.kind == "Template" 
  input.objects[_].kind == "Namespace"
  kinds := input.objects[_].kind
  missing_limit_range(kinds)
  missing_quoatas(kinds)
  msg := sprintf("Found a Namespace but no corresponding %s", [matchers])
}

missing_limit_range(kinds) {
  not kinds["LimitRange"]  
}

missing_quoatas(kinds) {
  not kinds["ResourceQuotas"]  
}
