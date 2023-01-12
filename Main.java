import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

    public static void main(String[] args) throws IOException, KeyStoreException, InvalidKeyException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, IllegalBlockSizeException, BadPaddingException {
        // Load properties file
        if (args.length != 1) {
            System.out.println("Usage: HybridEncryptor <config file>");
            return;
        }
        EncryptionPropertiesParser propertiesParser = new EncryptionPropertiesParser(args[0]);
        HybridEncryptor encryptor = new HybridEncryptor(propertiesParser);
        //encryptor.run();

        DecryptionPropertiesParser decryptionPropertiesParser = new DecryptionPropertiesParser(propertiesParser.getOutConfigFile());
        HybridDecryptor decryptor = new HybridDecryptor(decryptionPropertiesParser);
        decryptor.run();
    }
}