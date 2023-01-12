import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.SecretKey;

public class PropertiesParser {
    private String outputFile;

    private String keyStorePath;

    private String privateKeyStorePassword;

    private String AsymetricAlgorithm;

    private String SymetricAlgorithm;

    private String inputFile;

    private String KeyStoreType;

    private String outConfigFile;

    private String privateKeyPassword;

    private String keyStorePassword;

    private String encryptionkeyAlias;

    PropertiesParser(String filePath) throws IOException {
        // Load properties file
        Properties properties = new Properties();
        properties.load(new FileInputStream(filePath));
        inputFile = properties.getProperty("inputFile");
        outputFile = properties.getProperty("outputFile");
        keyStorePath = properties.getProperty("keyStoreFile");
        AsymetricAlgorithm = properties.getProperty("AsymetricAlgorithm");
        SymetricAlgorithm = properties.getProperty("SymetricAlgorithm");
        KeyStoreType = properties.getProperty("KeyStoreType");
        // privateKeyPassword = properties.getProperty("privateKeyPassword");
        keyStorePassword = properties.getProperty("KeyStorePassword");
        encryptionkeyAlias = properties.getProperty("keyAlias");
        outConfigFile = properties.getProperty("outConfigFile");
    }

    public String getOutputFile() {
        return outputFile;
    }

    public String getInputFile() {
        return inputFile;
    }

    public String getOutConfigFile() {
        return outConfigFile;
    }

    private KeyStore getKeyStore()
            throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
            KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(this.KeyStoreType);
        keyStore.load(new FileInputStream(this.keyStorePath), this.keyStorePassword.toCharArray());
        return keyStore;
    }

    public Key getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        return getKeyStore().getKey(this.encryptionkeyAlias, this.keyStorePassword.toCharArray());
    }

    public Key getPublicKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        return getKeyStore().getCertificate(this.encryptionkeyAlias).getPublicKey();
    }

    public Certificate getCertificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException {
        return getKeyStore().getCertificate(this.encryptionkeyAlias);
    }

    public String getAsymetricAlgorithm() {
        return AsymetricAlgorithm;
    }

    public String getSymetricAlgorithm() {
        return SymetricAlgorithm;
    }

    public Properties getDecryptionConfig() {
        Properties properties = new Properties();
        properties.setProperty("inputFile", this.outputFile);
        properties.setProperty("keyStoreFile", this.keyStorePath);
        properties.setProperty("KeyStorePassword", this.keyStorePassword);
        properties.setProperty("AsymetricAlgorithm", this.AsymetricAlgorithm);
        properties.setProperty("SymetricAlgorithm", this.SymetricAlgorithm);
        properties.setProperty("KeyStoreType", this.KeyStoreType);
        properties.setProperty("keyAlias", this.encryptionkeyAlias);
        return properties;
    }

}