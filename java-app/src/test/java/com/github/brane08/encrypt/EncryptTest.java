package com.github.brane08.encrypt;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EncryptTest {

	static final byte[] KEY = new byte[]{
			0x59, 0x79, 0x4c, 0x44, 0x68, 0x35, 0x34, 0x4b, 0x51, 0x4f, 0x76, 0x24, 0x62, 0x50, 0x61, 0x46,
			0x6b, 0x4a, 0x5a, 0x66, 0x77, 0x6f, 0x70, 0x36, 0x21, 0x25, 0x53, 0x4d, 0x6a, 0x55, 0x6d, 0x6c};

	// Produced by python-app/python/aes.py
	static final String PYTHON_PAYLOAD = "6SWNCZiwaR52Kj/CQzGHroNu/m549KX245TIZdx7ssL+X8OTAGG1Uw==";

	final AesGcmCipher cipher = new AesGcmCipher(KEY);

	@Test
	public void roundTrip() throws GeneralSecurityException {
		String payload = cipher.encrypt("SomePassword");
		System.out.println("JAVA_PAYLOAD=" + payload);
		assertEquals("SomePassword", cipher.decrypt(payload));
	}

	@Test
	public void nonceIsRandom() throws GeneralSecurityException {
		assertNotEquals(cipher.encrypt("x"), cipher.encrypt("x"));
	}

	@Test
	public void decryptsPythonPayload() throws GeneralSecurityException {
		assertEquals("SomePassword", cipher.decrypt(PYTHON_PAYLOAD));
	}

	@Test
	public void tamperedPayloadRejected() throws GeneralSecurityException {
		byte[] raw = java.util.Base64.getDecoder().decode(cipher.encrypt("SomePassword"));
		raw[raw.length - 1] ^= 1;
		String tampered = java.util.Base64.getEncoder().encodeToString(raw);
		assertThrows(GeneralSecurityException.class, () -> cipher.decrypt(tampered));
	}
}
