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

public class EncryptionPropertiesParser {
    private String outputFile;

    private String decryptedOutputFile;

    private String AsymetricAlgorithm;

    private String SymetricAlgorithm;

    private String HashAlgorithm;

    private String inputFile;

    private String KeyStoreType;

    private String outConfigFile;

    private String senderKeyStorePath;

    private String senderKeyStorePassword;

    private String senderEncryptionkeyAlias;

    private String senderCertificateAlias;

    private String receiverKeyStorePath;

    private String receiverKeyStorePassword;

    private String receiverEncryptionkeyAlias;

    private String receiverCertificateAlias;

    EncryptionPropertiesParser(String filePath) throws IOException {
        // Load properties file
        Properties properties = new Properties();
        properties.load(new FileInputStream(filePath));
        inputFile = properties.getProperty("inputFile");
        outputFile = properties.getProperty("outputFile");
        decryptedOutputFile = properties.getProperty("decryptedOutputFile");
        KeyStoreType = properties.getProperty("KeyStoreType");
        AsymetricAlgorithm = properties.getProperty("AsymetricAlgorithm");
        SymetricAlgorithm = properties.getProperty("SymetricAlgorithm");
        HashAlgorithm = properties.getProperty("HashAlgorithm");
        outConfigFile = properties.getProperty("outConfigFile");

        senderKeyStorePath = properties.getProperty("sender.keyStoreFile");
        senderKeyStorePassword = properties.getProperty("sender.KeyStorePassword");
        senderEncryptionkeyAlias = properties.getProperty("sender.keyAlias");
        senderCertificateAlias = properties.getProperty("sender.certificateAlias");

        receiverKeyStorePath = properties.getProperty("receiver.keyStoreFile");
        receiverKeyStorePassword = properties.getProperty("receiver.KeyStorePassword");
        receiverEncryptionkeyAlias = properties.getProperty("receiver.keyAlias");
        receiverCertificateAlias = properties.getProperty("receiver.certificateAlias");
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
        keyStore.load(new FileInputStream(this.senderKeyStorePath), this.senderKeyStorePassword.toCharArray());
        return keyStore;
    }

    public Key getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {

        return getKeyStore().getKey(this.senderEncryptionkeyAlias, this.senderKeyStorePassword.toCharArray());
    }

    public Key getReceiverPublicKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        return getReceiverCertificate().getPublicKey();
    }

    public Certificate getReceiverCertificate()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException {
        return getKeyStore().getCertificate(this.receiverCertificateAlias);
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

    public Properties getDecryptionConfig() {
        Properties properties = new Properties();
        properties.setProperty("inputFile", this.outputFile);
        properties.setProperty("outputFile", this.decryptedOutputFile);
        properties.setProperty("KeyStoreType", this.KeyStoreType);
        properties.setProperty("AsymetricAlgorithm", this.AsymetricAlgorithm);
        properties.setProperty("SymetricAlgorithm", this.SymetricAlgorithm);
        properties.setProperty("HashAlgorithm", this.HashAlgorithm);
        properties.setProperty("receiver.keyStoreFile", this.receiverKeyStorePath);
        properties.setProperty("receiver.keyStorePassword", this.receiverKeyStorePassword);
        properties.setProperty("receiver.encryptionkeyAlias", this.receiverEncryptionkeyAlias);
        properties.setProperty("sender.certificateAlias", this.senderCertificateAlias);

        return properties;
    }

}