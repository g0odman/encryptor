import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
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
import javax.crypto.spec.IvParameterSpec;
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
        String algorithmName = properties.getSymetricAlgorithm().split("/")[0];
        javax.crypto.SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, algorithmName);
        return secretKey;
    }

    boolean doesAlgorithmUseIV() {
        String algorithm = properties.getSymetricAlgorithm();
        String[] parts = algorithm.split("/");
        if (parts.length < 2) {
            return false;
        }
        return parts[1].equals("CBC");
    }

    private void decryptFile(SecretKey secretKey) throws KeyStoreException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        // Decrypt file
        Cipher cipher = Cipher.getInstance(properties.getSymetricAlgorithm());
        if (doesAlgorithmUseIV()) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
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
            NoSuchProviderException, InvalidAlgorithmParameterException {

        if (!verifySignature()) {
            throw new InvalidSignatureException();

        }
        System.out.println("Signature verified!");
        SecretKey secretKey = decryptSecretKey();
        decryptFile(secretKey);
    }
}