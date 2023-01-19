import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

    public static void main(String[] args) throws IOException, KeyStoreException, InvalidKeyException,
            UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException,
            IllegalBlockSizeException, BadPaddingException, InvalidSignatureException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        // Load properties file
        if (args.length != 2) {
            System.out.println("Usage: HybridEncryptor [e|d] <config file> \n\te is to encrypt and d is to decrypt");
            return;
        }
        String mode = args[0];
        String configFile = args[1];
        switch (mode.charAt(0)) {
            case 'e':
                encrypt(configFile);
                break;
            case 'd':
                decrypt(configFile);
                break;
            default:
                System.out.println("Usage: HybridEncryptor [e|d] <config file>");
                System.out.println("\te is to encrypt and d is to decrypt");
                return;
        }
        System.out.println("Done!");
    }

    private static void decrypt(
            String ConfigFileName) throws IOException, KeyStoreException,
            NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException, NoSuchPaddingException,
            CertificateException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException,
            InvalidSignatureException, NoSuchProviderException, InvalidAlgorithmParameterException {
        System.out.println("Decrypting!");
        DecryptionPropertiesParser decryptionPropertiesParser = new DecryptionPropertiesParser(
                ConfigFileName);
        HybridDecryptor decryptor = new HybridDecryptor(decryptionPropertiesParser);
        decryptor.run();
    }

    private static void encrypt(String ConfigFileName) throws KeyStoreException,
            NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException, NoSuchPaddingException,
            CertificateException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, IOException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        System.out.println("Encrypting!");
        EncryptionPropertiesParser propertiesParser = new EncryptionPropertiesParser(ConfigFileName);
        HybridEncryptor encryptor = new HybridEncryptor(propertiesParser);
        encryptor.run();
    }
}