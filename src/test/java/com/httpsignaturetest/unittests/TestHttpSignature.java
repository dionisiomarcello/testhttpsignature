package com.httpsignaturetest.unittests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.httpsignaturetest.Constants;
import com.httpsignaturetest.SignatureBuilder;
import com.httpsignaturetest.Encryptor;

public class TestHttpSignature {
	private static final String JSON_TEST_CONTENT = "{\"field\":\"value\"}";

	@Test
	public void testGet() throws Exception {
		System.out.println("Testing HTTP Get with a custom header X-Example, date and Digest headers");
		try (CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpGet httpGet = new HttpGet(Constants.URL);
			SignatureBuilder builder = SignatureBuilder.newInstance();
			builder.keyId(Constants.KEY_ID).requestTarget("get".concat(" ").concat(Constants.PATH));
			Date now = new Date();
			String dateHeader = new SimpleDateFormat(Constants.DATE_FORMAT, Locale.US).format(now);
			builder.addHeader("Date", dateHeader);
			builder.addHeader("X-Example", "example");
			builder.addHeader("Digest", Encryptor.generateRandomDigest());

			Map<String, String> headers = builder.getHeaders();
			for (String key : headers.keySet()) {
				if ("content-length".equals(key)) {
					// content length header not necessary since HttpClient already handles it
					continue;
				}
				httpGet.addHeader(key, headers.get(key));
			}
			httpGet.addHeader("Authorization", builder.build());
			
			try (CloseableHttpResponse response = httpclient.execute(httpGet);) {
				assertEquals(200, response.getStatusLine().getStatusCode());
				HttpEntity entity = response.getEntity();
				try (BufferedReader br = new BufferedReader(
						new InputStreamReader(entity.getContent(), Charset.forName("UTF-8")))) {
					String responseStr = br.lines().collect(Collectors.joining(System.lineSeparator()));
					ObjectMapper mapper = new ObjectMapper();
					ObjectNode responseJson = (ObjectNode) mapper.readTree(responseStr);
					String role = ((ObjectNode) responseJson.get("authentication_key")).get("role").asText();
					assertEquals("DEVICE", role);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPost() throws Exception {
		System.out.println("Testing HTTP POST with a custom header X-Example, date and Digest headers and a simple JSON request body");
		try (CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpPost httpPost = new HttpPost(Constants.URL);
			SignatureBuilder builder = SignatureBuilder.newInstance();
			builder.keyId(Constants.KEY_ID).requestTarget("post".concat(" ").concat(Constants.PATH));
			Date now = new Date();
			String dateHeader = new SimpleDateFormat(Constants.DATE_FORMAT, Locale.US).format(now);
			builder.addHeader("Date", dateHeader);
			builder.addHeader("X-Example", "example");
			builder.addHeader("Content-Type", "application/json");
			builder.addHeader("Content-Length", Integer.toString(JSON_TEST_CONTENT.length()));
			builder.addHeader("Digest", Encryptor.generateRandomDigest());

			Map<String, String> headers = builder.getHeaders();
			for (String key : headers.keySet()) {
				if ("content-length".equals(key)) {
					// content length header not necessary since HttpClient already handles it
					continue;
				}
				httpPost.addHeader(key, headers.get(key));
			}
			httpPost.addHeader("Authorization", builder.build());
			httpPost.setEntity(new StringEntity(JSON_TEST_CONTENT));
			try (CloseableHttpResponse response = httpclient.execute(httpPost);) {
				assertEquals(200, response.getStatusLine().getStatusCode());
				HttpEntity entity = response.getEntity();
				try (BufferedReader br = new BufferedReader(
						new InputStreamReader(entity.getContent(), Charset.forName("UTF-8")))) {
					String responseStr = br.lines().collect(Collectors.joining(System.lineSeparator()));
					ObjectMapper mapper = new ObjectMapper();
					ObjectNode responseJson = (ObjectNode) mapper.readTree(responseStr);
					String role = ((ObjectNode) responseJson.get("authentication_key")).get("role").asText();
					assertEquals("DEVICE", role);
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPut() throws Exception {
		System.out.println("Testing HTTP PUT with a custom header X-Example, date and Digest headers and a simple JSON request body");
		try (CloseableHttpClient httpclient = HttpClients.createDefault();) {
			HttpPut httpPut = new HttpPut(Constants.URL);
			SignatureBuilder builder = SignatureBuilder.newInstance();
			builder.keyId(Constants.KEY_ID).requestTarget("put".concat(" ").concat(Constants.PATH));
			Date now = new Date();
			String dateHeader = new SimpleDateFormat(Constants.DATE_FORMAT, Locale.US).format(now);
			builder.addHeader("Date", dateHeader);
			builder.addHeader("X-Example", "example");
			builder.addHeader("Content-Type", "application/json");
			builder.addHeader("Content-Length", Integer.toString(JSON_TEST_CONTENT.length()));
			builder.addHeader("Digest", Encryptor.generateRandomDigest());

			Map<String, String> headers = builder.getHeaders();
			for (String key : headers.keySet()) {
				if ("content-length".equals(key)) {
					// content length header not necessary since HttpClient already handles it
					continue;
				}
				httpPut.addHeader(key, headers.get(key));
			}
			httpPut.setEntity(new StringEntity(JSON_TEST_CONTENT));
			httpPut.addHeader("Authorization", builder.build());
			
			try (CloseableHttpResponse response = httpclient.execute(httpPut);) {
				assertEquals(200, response.getStatusLine().getStatusCode());
				HttpEntity entity = response.getEntity();
				try (BufferedReader br = new BufferedReader(
						new InputStreamReader(entity.getContent(), Charset.forName("UTF-8")))) {
					String responseStr = br.lines().collect(Collectors.joining(System.lineSeparator()));
					ObjectMapper mapper = new ObjectMapper();
					ObjectNode responseJson = (ObjectNode) mapper.readTree(responseStr);
					String role = ((ObjectNode) responseJson.get("authentication_key")).get("role").asText();
					assertEquals("DEVICE", role);
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testDelete() throws Exception {
		System.out.println("Testing HTTP DELETE with a custom header X-Example, date and Digest headers");
		try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
			HttpDelete httpDelete = new HttpDelete(Constants.URL);
			SignatureBuilder builder = SignatureBuilder.newInstance();
			builder.keyId(Constants.KEY_ID).requestTarget("delete".concat(" ").concat(Constants.PATH));
			Date now = new Date();
			String dateHeader = new SimpleDateFormat(Constants.DATE_FORMAT, Locale.US).format(now);
			builder.addHeader("Date", dateHeader);
			builder.addHeader("X-Example", "example");
			builder.addHeader("Digest", Encryptor.generateRandomDigest());

			Map<String, String> headers = builder.getHeaders();
			for (String key : headers.keySet()) {
				if ("content-length".equals(key)) {
					// content length header not necessary since HttpClient already handles it
					continue;
				}
				httpDelete.addHeader(key, headers.get(key));
			}
			httpDelete.addHeader("Authorization", builder.build());
			
			try (CloseableHttpResponse response = httpclient.execute(httpDelete)) {
				assertEquals(200, response.getStatusLine().getStatusCode());
				HttpEntity entity = response.getEntity();
				try (BufferedReader br = new BufferedReader(
						new InputStreamReader(entity.getContent(), Charset.forName("UTF-8")))) {
					String responseStr = br.lines().collect(Collectors.joining(System.lineSeparator()));
					ObjectMapper mapper = new ObjectMapper();
					ObjectNode responseJson = (ObjectNode) mapper.readTree(responseStr);
					String role = ((ObjectNode) responseJson.get("authentication_key")).get("role").asText();
					assertEquals("DEVICE", role);
				}
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

}
