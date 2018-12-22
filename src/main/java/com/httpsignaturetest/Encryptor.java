package com.httpsignaturetest;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.io.IOUtils;

/**
 * Class responsible for encrypting the signature using a provided private key
 * file
 */
public class Encryptor {
	private static final String PRIVATE_KEY_FILE_PATH = "client-rsa-private-key.pem";

	private static String signSHA256RSA(String input) throws Exception {
		String realPK;
		try (InputStream is = Encryptor.class.getClassLoader().getResourceAsStream(PRIVATE_KEY_FILE_PATH);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			IOUtils.copy(is, baos);
			realPK = new String(baos.toByteArray()).replaceAll("-----END PRIVATE KEY-----", "")
					.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("\n", "");
		}
		byte[] b1 = Base64.getDecoder().decode(realPK);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
		KeyFactory kf = KeyFactory.getInstance("RSA");

		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(kf.generatePrivate(spec));
		privateSignature.update(input.getBytes("UTF-8"));
		byte[] s = privateSignature.sign();
		return Base64.getEncoder().encodeToString(s);
	}

	public static String encryptSignature(String requestTarget, Map<String, String> headers) throws Exception {
		String signature = "(request-target): ".concat(requestTarget);
		for (String headerName : headers.keySet()) {
			signature = signature.concat("\n");
			signature = signature.concat(headerName.toLowerCase()).concat(": ").concat(headers.get(headerName));
		}
		return signSHA256RSA(signature);
	}

	public static String generateRandomDigest() {
		return Base64.getEncoder()
				.encodeToString(UUID.randomUUID().toString().getBytes());
	}
}
