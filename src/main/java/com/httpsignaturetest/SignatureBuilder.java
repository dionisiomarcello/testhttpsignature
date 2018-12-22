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

	/**
	 * Creates a new instance of a <code>SignatureBuilder</code>
	 * 
	 * @return e new <code>SignatureBuilder</code>
	 */
	public static SignatureBuilder newInstance() {
		return new SignatureBuilder();
	}

	/**
	 * Sets the value of the request-target special header
	 * 
	 * @param requestTarget the value of the request-target header (See RFC7540)
	 * @return this <code>SignatureBuilder</code>
	 */
	public SignatureBuilder requestTarget(String requestTarget) {
		this.requestTarget = requestTarget;
		return this;
	}

	/**
	 * Sets the value of the keyId parameter
	 * 
	 * @param keyId the value of the keyId parameter
	 * @return this <code>SignatureBuilder</code>
	 */
	public SignatureBuilder keyId(String keyId) {
		this.keyId = keyId;
		return this;
	}

	/**
	 * Adds a new HTTP header
	 * @param headerName the name of the HTTP header
	 * @param headerValue the header value
	 * @return this <code>SignatureBuilder</code>
	 */
	public SignatureBuilder addHeader(String headerName, String headerValue) {
		this.headers.put(headerName.toLowerCase(), headerValue);
		return this;
	}

	/**
	 * Gets the map of HTTP headers
	 * @return the map of HTTP headers
	 */
	public Map<String, String> getHeaders() {
		return this.headers;
	}

	/**
	 * Generates a new HTTP signature using the values set in the previous steps
	 * @return the HTTP signature string
	 * @throws Exception in case an error occurs
	 */
	public String build() throws Exception {
		String headersSection = Joiner.on(" ").join(Sets.union(Sets.newHashSet("(request-target)"), headers.keySet()));
		return String.format(SIGNATURE_PATTERN, keyId, headersSection,
				Encryptor.encryptSignature(requestTarget, headers));
	}
}
