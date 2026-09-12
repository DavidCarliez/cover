package activity

// Messages are fixed text. Never include provider errors or request values.
func Explain(code string, status int) (string, string) {
	switch code {
	case "request_too_large":
		return "Request exceeds Cover's size limit.", "Start a shorter chat or increase limits.request_bytes."
	case "response_too_large":
		return "Response exceeds Cover's size limit.", "Request smaller output or increase limits.response_bytes."
	case "sse_event_too_large":
		return "Stream event or restoration queue exceeds Cover's limit.", "Reduce output size or increase limits.sse_event_bytes."
	case "policy_blocked":
		return "A local privacy rule blocked the request.", "Review your block rules with cover inspect."
	case "upstream_idle_timeout":
		return "Provider stopped sending response data.", "Retry; for slow providers, adjust upstream_timeouts.response_idle_timeout_ms."
	case "upstream_timeout":
		return "Provider did not connect or send headers in time.", "Check the provider and upstream_timeouts settings."
	case "upstream_connection_failed":
		return "Could not complete the provider connection.", "Check the router, network, and Cover upstream URL."
	case "unsupported_compression":
		return "Compressed request cannot be inspected.", "Run cover doctor and disable request compression in the client."
	case "unsafe_request":
		return "Request could not be safely inspected.", "Run cover doctor; check request format and mapping limits."
	case "stream_interrupted":
		return "Stream ended with a transport error.", "Retry the request and check the provider connection."
	case "client_cancelled":
		return "Client cancelled the request.", "No action needed if you stopped the turn."
	}
	switch status {
	case 401, 403:
		return "Request was rejected.", "Check provider authentication; consult Cover's log for local policy failures."
	case 429:
		return "Provider rate limit reached.", "Wait before retrying."
	}
	return "", ""
}
