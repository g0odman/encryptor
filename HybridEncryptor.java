import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

class HybridEncryptor {

    private PropertiesParser properties;

    HybridEncryptor(PropertiesParser properties) throws KeyStoreException {
        this.properties = properties;
    }

    private void encryptFile(SecretKey secretKey) throws KeyStoreException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        // Encrypt file
        Cipher cipher = Cipher.getInstance(properties.getSymetricAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
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

    private SecretKey generateSecreteKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(properties.getSymetricAlgorithm());
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private void generateDecryptionConfig(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, UnrecoverableKeyException, KeyStoreException, CertificateException,
            FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException {
        // Encrypt secret key
        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, properties.getPublicKey());
        byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());

        // Write encrypted secret key and encrypted file to output file
        FileOutputStream encryptedOut = new FileOutputStream(properties.getOutConfigFile());
        encryptedOut.write(encryptedSecretKey);
        encryptedOut.close();
        Properties outProps = properties.getDecryptionConfig();
        outProps.setProperty("secretKey", encryptedSecretKey.toString());
        outProps.setProperty("digitalSignature", signFile().toString());
        // Write properties to file
        FileOutputStream out = new FileOutputStream(properties.getOutConfigFile());
        outProps.store(out, "Encryption Configuration");
        out.close();
    }

    private byte[] signFile() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        // Sign file
        Cipher cipher = Cipher.getInstance(properties.getAsymetricAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, properties.getPrivateKey());
        FileInputStream in = new FileInputStream(properties.getInputFile());
        byte[] buffer = new byte[1024];
        int numRead;
        while ((numRead = in.read(buffer)) >= 0) {
            cipher.update(buffer, 0, numRead);
        }
        in.close();
        return cipher.doFinal();
    }

    public void run() throws NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException,
            NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        SecretKey secretKey = generateSecreteKey();
        encryptFile(secretKey);
        generateDecryptionConfig(secretKey);
    }
}