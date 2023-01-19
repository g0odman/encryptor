import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

class HybridEncryptor {

    private EncryptionPropertiesParser properties;

    HybridEncryptor(EncryptionPropertiesParser properties) throws KeyStoreException {
        this.properties = properties;
    }

    private void encryptFile(SecretKey secretKey) throws KeyStoreException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException, NoSuchProviderException {
        // Encrypt file
        Cipher cipher = Cipher.getInstance(properties.getSymetricAlgorithm(), properties.getProvider());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        System.out.println("Encrypting file: " + properties.getInputFile());
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

    private String getAlgorithmName() {
        String algorithm = properties.getSymetricAlgorithm();
        String[] parts = algorithm.split("/");
        return parts[0];
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException, NoSuchPaddingException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(getAlgorithmName());
        keyGenerator.init(properties.getSymmetricKeyLength());
        SecretKey newKey = keyGenerator.generateKey();
        return newKey;
    }

    private void generateDecryptionConfig(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, UnrecoverableKeyException, KeyStoreException, CertificateException,
            FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException {
        // Encrypt secret key
        String encodedEncryptedSecretKey = encryptSecretKey(secretKey);
        byte[] fileSignature = signFile();
        String encodedFileSignature = new String(Base64.getEncoder().encodeToString(fileSignature));

        Properties outProps = properties.getDecryptionConfig();
        outProps.setProperty("secretKey", encodedEncryptedSecretKey);
        outProps.setProperty("digitalSignature", encodedFileSignature);
        // Write properties to file
        System.out.println("Writing decryption configuration to file: " + properties.getOutConfigFile());
        FileOutputStream out = new FileOutputStream(properties.getOutConfigFile());
        outProps.store(out, "Decryption Configuration");
        out.close();
    }

    private String encryptSecretKey(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, UnrecoverableKeyException, KeyStoreException, CertificateException,
            FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm(), properties.getProvider());
        cipher.init(Cipher.ENCRYPT_MODE, properties.getReceiverPublicKey());
        byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());
        String encodedEncryptedSecretKey = new String(Base64.getEncoder().encodeToString(encryptedSecretKey));
        return encodedEncryptedSecretKey;
    }

    private byte[] signFile() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException {
        // Sign file
        MessageDigest messageDigest = MessageDigest.getInstance(properties.getHashAlgorithm());
        FileInputStream in = new FileInputStream(properties.getOutputFile());
        byte[] buffer = new byte[1024];
        while (in.read(buffer) >= 0) {
            messageDigest.update(buffer);
        }
        in.close();
        byte[] hash = messageDigest.digest();

        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm(), properties.getProvider());

        cipher.init(Cipher.ENCRYPT_MODE, properties.getPrivateKey());
        return cipher.doFinal(hash);
    }

    public void run() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        SecretKey secretKey = generateSecretKey();

        encryptFile(secretKey);
        generateDecryptionConfig(secretKey);
    }
}