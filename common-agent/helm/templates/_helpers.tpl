{{/*
Common prefix prepended to Kubernetes resources of this chart
*/}}
{{- define "common-agent-helm.resource.prefix" -}}
{{- printf "%s-wso2-agent" .Release.Name -}}
{{- end -}}
