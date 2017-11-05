package com.fahamu.tech;

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

public class FileEncrypt {
    /*
    the key is used to encrypt and decrypt a file
    the key is 16 byte , you can change it to anything.
    check for key length of AES or you can change to any algorithm.
    check :-  https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html

    //to test the length of the key try this, until you get right length

    String key ="<your key>";
    System.out.println(key.length());

    */

    //this key is for illustration only, substitute it with yours
    //you can use "Mary has one cat" as an example
    public static final String KEY="Mary has one cat";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    /**
     *
     * @param key=the string to be used as a key with a required length
     * @param inputFile=the file location/path for encryption
     * @param outputFile=the file path/location to save the encryption  file
     * @throws IOException=thrown if there is failure
     */
    public void encrypt(String key, File inputFile, File outputFile)
            throws IOException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    /**
     *
     * @param key=the string to be used as a key with a required length
     * @param inputFile=the file location/path for decryption
     * @param outputFile=the file path/location to save the decryption  file
     * @throws IOException=thrown if there is failure
     */
    public void decrypt(String key, File inputFile, File outputFile)
            throws IOException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    /**
     *  //this is the common method used to encrypt and decrypt a file
     * @param cipherMode=specify either is encryption or decryption
     * @param key=key used to encrypt a file
     * @param inputFile=the file to deal with
     * @param outputFile=the output file to which is encrypted or decrypted
     * @throws IOException=thrown whenever there is a failure in processing a file
     */
    private void doCrypto(int cipherMode, String key, File inputFile,
                          File outputFile) throws IOException {
        try {
            Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

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

}