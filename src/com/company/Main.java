package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

	private static byte[] IV = new byte[16];
	private static String file1 = "test";
	private static String file2 = "test2";
	private static String encryptedFile = "encrypted_test2";

	public static void main(String[] args) {

		String keystorePath = args[0];
		String keyAlias = args[1];

		Scanner scanner = new Scanner(System.in);
		System.out.print("Enter password to the keystore: ");
		String password = scanner.nextLine();

		SecretKey secretKey;
		File file = new File(keystorePath);
		if (!file.exists())
			createNewKeystore(file, password.toCharArray(), keyAlias);

		secretKey = getSecretKey(file, password.toCharArray(), keyAlias);

		byte firstMessage[] = getFirst16Bytes(new File(file1));

		byte xoredMessage[] = xor(firstMessage, IV);
		IV[15] = 0x1;
		xoredMessage = xor(xoredMessage, IV);

		byte c1[] = encryptBytes(secretKey, xoredMessage);
		byte secondMessage[] = getFirst16Bytes(new File(file2));

		System.out.println("First message:\t\t\t" + Arrays.toString(firstMessage));
		System.out.println("Second message:\t\t\t" + Arrays.toString(secondMessage));
		System.out.println("Encrypted 1st message:\t" + Arrays.toString(c1));

		byte[] cipherText = getFirst16Bytes(new File(encryptedFile));
		System.out.println("Cipher text:\t\t\t" + Arrays.toString(cipherText));

		System.out.print("Encrypted file is ");

		if (Arrays.equals(cipherText, c1))
			System.out.print(file1);
		else
			System.out.print(file2);
	}

	private static byte[] xor(byte[] array1, byte[] array2) {
		byte[] results = new byte[array1.length];
		int i = 0;
		for (byte b : array1) {
			results[i] = (byte) (b ^ array2[i++]);
		}
		return results;
	}

	//region Create keystore
	private static void createNewKeystore(File file, char[] password, String keyAlias) {
		try {
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(file), password);

			// generate a secret key for AES encryption
			SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
			KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
			KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
			keyStore.setEntry(keyAlias, keyStoreEntry, keyPassword);
			keyStore.store(new FileOutputStream(file), password);


		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	//endregion

	//region get secret key from Keystore
	private static SecretKey getSecretKey(File file, char[] password, String keyAlias) {
		SecretKey key = null;
		try {
			InputStream fis = new FileInputStream(file);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(fis, password);

			KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);

			KeyStore.Entry entry = keyStore.getEntry(keyAlias, keyPassword);
			key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();


		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}
	//endregion

	private static byte[] encryptFirst16Bytes(SecretKey secretKey, String inputFileName) {
		try {

			FileInputStream fileInputStream = new FileInputStream(new File(inputFileName));
			BufferedInputStream reader = new BufferedInputStream(fileInputStream);
			byte[] buffer = new byte[16];

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

			IvParameterSpec ivSpec = new IvParameterSpec(IV);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			if (reader.read(buffer) > 0) {
				return cipher.doFinal(buffer);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] encryptBytes(SecretKey secretKey, byte[] input) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			IvParameterSpec ivSpec = new IvParameterSpec(IV);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			return cipher.doFinal(input);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;

	}

	private static byte[] getFirst16Bytes(File file) {
		try {
			FileInputStream fileInputStream = new FileInputStream(file);
			BufferedInputStream reader = new BufferedInputStream(fileInputStream);
			byte[] buffer = new byte[16];
			if (reader.read(buffer) > 0)
				return buffer;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
