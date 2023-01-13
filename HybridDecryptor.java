import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class HybridDecryptor {

    private DecryptionPropertiesParser properties;

    HybridDecryptor(DecryptionPropertiesParser properties) throws KeyStoreException {
        this.properties = properties;
    }

    private SecretKey decryptSecretKey() throws NoSuchAlgorithmException, NoSuchPaddingException, 
    InvalidKeyException, UnrecoverableKeyException, KeyStoreException, CertificateException, 
    FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException {
        String encryptedSecretKey = properties.getSecretKey();
        byte[] decodedEncryptedSecretKey = Base64.getDecoder().decode(encryptedSecretKey);
        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, properties.getPrivateKey());
        byte[] decryptedSecretKey = cipher.doFinal(decodedEncryptedSecretKey);
        //byte[] decryptedSecretKey = encryptedSecretKey;
        javax.crypto.SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, properties.getSymetricAlgorithm());
        return secretKey;
    }

    private void decryptFile(SecretKey secretKey) throws KeyStoreException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        // Decrypt file
        Cipher cipher = Cipher.getInstance(properties.getSymetricAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        // IvParameterSpec iv = new IvParameterSpec(cipher.getIV());
        FileInputStream in = new FileInputStream(properties.getInputFile());
        CipherOutputStream out = new CipherOutputStream(new FileOutputStream(properties.getOutputFile()), cipher);
        byte[] buffer = new byte[1024];
        int numRead;
        while ((numRead = in.read(buffer)) >= 0) {
            out.write(buffer, 0, numRead);
        }
        in.close();
        out.close();

    }

    private boolean verifySignature() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        // Verify Digital Signature
        FileInputStream in = new FileInputStream(properties.getInputFile());
        byte[] buffer = new byte[1024];
        while (in.read(buffer) >= 0) { }
        in.close();
        
        MessageDigest messageDigest = MessageDigest.getInstance(properties.getHashAlgorithm());
        byte[] hash = messageDigest.digest(buffer);

        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, properties.getSenderPublicKey());

        String encodedSignature = properties.getDigitalSignature();
        byte[] decodedSignature = Base64.getDecoder().decode(encodedSignature);
        byte[] decryptedSignature = cipher.doFinal(decodedSignature);
        if (Arrays.equals(decryptedSignature, hash)) {
            return true;
        }
        return false;
    }

    public void run() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        
        if (verifySignature()) {
            System.out.println("Received legal signature, decrypting");
            SecretKey secretKey = decryptSecretKey();
            decryptFile(secretKey);
        }
        else {
            System.out.println("Bad Signature!");
        }
    }
}