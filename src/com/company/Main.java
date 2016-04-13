package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.KeyStore;
import java.util.Scanner;

public class Main {

    private static byte[] IV = new byte[16];
    private static String file1 = "test2";
    private static String file2 = "encrypted_test";

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

        byte encryptedFile1[] = encryptFirst16Bytes(secretKey, file1);
        byte encryptedFile2[] = encryptFirst16Bytes(secretKey, file2);
        IV[15] = 0x1;

        byte encryptedFile1b[] = encryptFirst16Bytes(secretKey, file1);
        String encryptedFileName = encryptedFile1 == encryptedFile1b ? file1 : file2;
        System.out.println("Encrypted file is " + encryptedFileName);

    }

    private static byte[] xor(byte[] array1, byte[] array2){
        byte[] results = new byte[array1.length];
        int i =0;
        for(byte b : array1){
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
}
