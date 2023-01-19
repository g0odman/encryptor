import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
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
            FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException {
        String encryptedSecretKey = properties.getSecretKey();
        byte[] decodedEncryptedSecretKey = Base64.getDecoder().decode(encryptedSecretKey);
        Cipher cipher = null;
        if (properties.getProvider() == null)
            cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        else
            cipher = Cipher.getInstance(properties.getSymetricAlgorithm(), properties.getProvider());
        cipher.init(Cipher.DECRYPT_MODE, properties.getPrivateKey());
        byte[] decryptedSecretKey = cipher.doFinal(decodedEncryptedSecretKey);
        String algorithmName = properties.getSymetricAlgorithm().split("/")[0];
        SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, algorithmName);
        return secretKey;
    }

    private void decryptFile(SecretKey secretKey) throws KeyStoreException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException, NoSuchProviderException {
        // Decrypt file
        Cipher cipher = null;
        if (properties.getProvider() == null)
            cipher = Cipher.getInstance(properties.getSymetricAlgorithm());
        else
            cipher = Cipher.getInstance(properties.getSymetricAlgorithm(), properties.getProvider());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        System.out.println("Decrypting file: " + properties.getInputFile());
        System.out.println("Output file: " + properties.getOutputFile());
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
            IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException {
        System.out.println("Verifying signature...");
        MessageDigest messageDigest = calculateHash();

        byte[] hash = messageDigest.digest();

        Cipher cipher = null;
        if (properties.getProvider() == null)
            cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        else
            cipher = Cipher.getInstance(properties.getAsymetricAlgorithm(), properties.getProvider());
        cipher.init(Cipher.DECRYPT_MODE, properties.getSenderPublicKey());

        String encodedSignature = properties.getDigitalSignature();
        byte[] decodedSignature = Base64.getDecoder().decode(encodedSignature);
        byte[] decryptedSignature = cipher.doFinal(decodedSignature);
        return Arrays.equals(decryptedSignature, hash);
    }

    private MessageDigest calculateHash() throws FileNotFoundException, NoSuchAlgorithmException, IOException {
        FileInputStream in = new FileInputStream(properties.getInputFile());
        byte[] buffer = new byte[1024];
        MessageDigest messageDigest = MessageDigest.getInstance(properties.getHashAlgorithm());
        while (in.read(buffer) >= 0) {
            messageDigest.update(buffer);
        }
        in.close();
        return messageDigest;
    }

    public void run() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException, InvalidSignatureException,
            NoSuchProviderException {

        if (!verifySignature()) {
            throw new InvalidSignatureException();

        }
        System.out.println("Signature verified!");
        SecretKey secretKey = decryptSecretKey();
        decryptFile(secretKey);
    }
}