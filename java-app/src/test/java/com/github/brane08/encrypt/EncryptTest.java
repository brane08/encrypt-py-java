package com.github.brane08.encrypt;


import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class EncryptTest {

	byte[] key = new byte[]{
			(byte) 0x59, 0x79, 0x4c, 0x44, 0x68, 0x35, 0x34, 0x4b, 0x51, 0x4f, 0x76, 0x24, 0x62, 0x50, 0x61, 0x46,
			(byte) 0x6b, 0x4a, 0x5a, 0x66, 0x77, 0x6f, 0x70, 0x36, 0x21, 0x25, 0x53, 0x4d, 0x6a, 0x55, 0x6d, 0x6c};
	byte[] iv = new byte[]{
			(byte) 0x4d, 0x6a, 0x43, 0x64, 0x4a, 0x65, 0x4c, 0x71, 0x6b, 0x76, 0x4e, 0x29, 0x73, 0x78, 0x48, 0x35};
	String toEncrypt = "SomePassword";

	@Test
	public void testPrintKeys() {
		byte[] ivChars = "MjCdJeLqkvN)sxH5".getBytes(StandardCharsets.US_ASCII);
		List<String> ivList = new ArrayList<>();
		for (byte aChar : ivChars) {
			ivList.add(String.format("0x%02x", aChar));
		}
		System.out.println(String.join(",", ivList));
		byte[] keyBytes = "YyLDh54KQOv$bPaFkJZfwop6!%SMjUml".getBytes(StandardCharsets.US_ASCII);
		List<String> keyList = new ArrayList<>();
		for (byte aChar : keyBytes) {
			keyList.add(String.format("0x%02x", aChar));
		}
		System.out.println(String.join(",", keyList));
	}

	@Test
	public void testEncryptDecrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException,
			IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		String encrypted = encryptString(toEncrypt);
		System.out.println("Encrypted: " + encrypted);
		String decrypted = decryptString(encrypted);
		System.out.println("Decrypted: " + decrypted);
	}

	private String encryptString(String notEncrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, paramSpec);
		String enc = "";
		byte[] encrypted = cipher.doFinal(notEncrypted.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(encrypted);
	}

	private String decryptString(String encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, paramSpec);
		byte[] encBytes = Base64.getDecoder().decode(encrypted.getBytes());
		byte[] original = cipher.doFinal(encBytes);
		return new String(original);
	}
}
