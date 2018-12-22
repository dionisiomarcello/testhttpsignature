package com.httpsignaturetest;

import java.util.HashMap;
import java.util.Map;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;

/**
 * Builder class for http signature
 *
 */
public class SignatureBuilder {
	private static final String SIGNATURE_PATTERN = "Signature keyId=\"%s\", algorithm=\"rsa-sha256\", headers=\"%s\", signature=\"%s\"";

	private String requestTarget;
	private String keyId;
	private Map<String, String> headers;

	private SignatureBuilder() {
		this.requestTarget = "";
		this.keyId = "";
		this.headers = new HashMap<String, String>();
	}

	public static SignatureBuilder newInstance() {
		return new SignatureBuilder();
	}

	public SignatureBuilder requestTarget(String requestTarget) {
		this.requestTarget = requestTarget;
		return this;
	}

	public SignatureBuilder keyId(String keyId) {
		this.keyId = keyId;
		return this;
	}

	public SignatureBuilder addHeader(String headerName, String headerValue) {
		this.headers.put(headerName.toLowerCase(), headerValue);
		return this;
	}

	public Map<String, String> getHeaders() {
		return this.headers;
	}

	public String build() throws Exception {
		String headersSection = Joiner.on(" ").join(Sets.union(Sets.newHashSet("(request-target)"), headers.keySet()));
		return String.format(SIGNATURE_PATTERN, keyId, headersSection,
				Encryptor.encryptSignature(requestTarget, headers));
	}
}
