import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

public class DecryptionPropertiesParser {
    private String inputFile;

    private String outputFile;

    private String AsymetricAlgorithm;

    private String SymetricAlgorithm;

    private String HashAlgorithm;

    private String KeyStoreType;

    private String senderCertificateAlias;

    private String receiverKeyStorePath;

    private String receiverKeyStorePassword;

    private String receiverEncryptionkeyAlias;

    private String secretKey;

    private String digitalSignature;

    private String provider;

    DecryptionPropertiesParser(String filePath) throws IOException {
        // Load properties file
        Properties properties = new Properties();
        System.out.println("Loading Decryption Config from" + filePath);
        properties.load(new FileInputStream(filePath));
        inputFile = properties.getProperty("inputFile");
        outputFile = properties.getProperty("outputFile");
        KeyStoreType = properties.getProperty("KeyStoreType");
        AsymetricAlgorithm = properties.getProperty("AsymetricAlgorithm");
        SymetricAlgorithm = properties.getProperty("SymetricAlgorithm");
        HashAlgorithm = properties.getProperty("HashAlgorithm");
        provider = properties.getProperty("CryptoProvider");

        senderCertificateAlias = properties.getProperty("sender.certificateAlias");

        receiverKeyStorePath = properties.getProperty("receiver.keyStoreFile");
        receiverKeyStorePassword = properties.getProperty("receiver.keyStorePassword");
        receiverEncryptionkeyAlias = properties.getProperty("receiver.encryptionkeyAlias");

        secretKey = properties.getProperty("secretKey");
        digitalSignature = properties.getProperty("digitalSignature");
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getDigitalSignature() {
        return digitalSignature;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public String getInputFile() {
        return inputFile;
    }

    private KeyStore getKeyStore()
            throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
            KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(this.KeyStoreType);
        keyStore.load(new FileInputStream(this.receiverKeyStorePath), this.receiverKeyStorePassword.toCharArray());
        return keyStore;
    }

    public Key getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        return getKeyStore().getKey(this.receiverEncryptionkeyAlias, this.receiverKeyStorePassword.toCharArray());
    }

    public Key getSenderPublicKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        return getSenderCertificate().getPublicKey();
    }

    public Certificate getSenderCertificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException {
        return getKeyStore().getCertificate(this.senderCertificateAlias);
    }

    public String getAsymetricAlgorithm() {
        return AsymetricAlgorithm;
    }

    public String getSymetricAlgorithm() {
        return SymetricAlgorithm;
    }

    public String getHashAlgorithm() {
        return HashAlgorithm;
    }

    public String getProvider() {
        return provider;
    }

}