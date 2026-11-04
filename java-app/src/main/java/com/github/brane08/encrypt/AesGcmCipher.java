package com.github.brane08.encrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM. Payload = base64(nonce(12) || ciphertext || tag(16)).
 * Compatible with python-app/python/aes.py. Key: base64 32 bytes in env AES_KEY_B64.
 */
public final class AesGcmCipher {

	public static final String KEY_ENV = "AES_KEY_B64";
	private static final int NONCE_SIZE = 12;
	private static final int TAG_BITS = 128;
	private static final SecureRandom RANDOM = new SecureRandom();

	private final SecretKeySpec key;

	public AesGcmCipher(byte[] key) {
		if (key.length != 32) {
			throw new IllegalArgumentException("key must be 32 bytes, got " + key.length);
		}
		this.key = new SecretKeySpec(key, "AES");
	}

	public static AesGcmCipher fromEnv() {
		return fromEnv(KEY_ENV);
	}

	public static AesGcmCipher fromEnv(String envName) {
		String value = System.getenv(envName);
		if (value == null || value.isBlank()) {
			throw new IllegalStateException(envName + " is not set");
		}
		return new AesGcmCipher(Base64.getDecoder().decode(value.trim()));
	}

	public String encrypt(String plain) throws GeneralSecurityException {
		byte[] nonce = new byte[NONCE_SIZE];
		RANDOM.nextBytes(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
		byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
		byte[] out = new byte[NONCE_SIZE + ct.length];
		System.arraycopy(nonce, 0, out, 0, NONCE_SIZE);
		System.arraycopy(ct, 0, out, NONCE_SIZE, ct.length);
		return Base64.getEncoder().encodeToString(out);
	}

	public String decrypt(String payload) throws GeneralSecurityException {
		byte[] data = Base64.getDecoder().decode(payload);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_SIZE));
		byte[] plain = cipher.doFinal(data, NONCE_SIZE, data.length - NONCE_SIZE);
		return new String(plain, StandardCharsets.UTF_8);
	}
}
