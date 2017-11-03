package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

    public class Main {
        private static final String ALGORITHM = "AES";
        private static final String TRANSFORMATION = "AES";

        //encrypt a file
        public static void encrypt(String key, File inputFile, File outputFile)
                throws IOException{
            doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
        }

        public static void decrypt(String key, File inputFile, File outputFile)
                throws IOException {
            doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
        }

        private static void doCrypto(int cipherMode, String key, File inputFile,
                                     File outputFile) throws IOException {
            try {
                Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(cipherMode, secretKey);

                FileInputStream inputStream = new FileInputStream(inputFile);
                byte[] inputBytes = new byte[(int) inputFile.length()];
                int read = inputStream.read(inputBytes);
                System.out.println(read);

                byte[] outputBytes = cipher.doFinal(inputBytes);

                FileOutputStream outputStream = new FileOutputStream(outputFile);
                outputStream.write(outputBytes);

                inputStream.close();
                outputStream.close();

            } catch (NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidKeyException | BadPaddingException
                    | IllegalBlockSizeException | IOException ex) {
                ex.printStackTrace();
            }
        }

        public static void main(String[] args) {
            String key = "Mary has one cat";
            System.out.println(key.length());


            File inputFile = new File(System.getProperty("user.home"),"/Lb/serverCredential.db");
            File encryptedFile = new File("serverCredential.db.encrypted");
            File decryptedFile = new File("serverCredential.db.decrypted");

            try {
                encrypt(key, inputFile, encryptedFile);
                decrypt(key, encryptedFile, decryptedFile);
            } catch (IOException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }