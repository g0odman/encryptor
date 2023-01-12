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
        PropertiesParser propertiesParser = new PropertiesParser(args[0]);
        HybridEncryptor hybridEncryptor = new HybridEncryptor(propertiesParser);
        hybridEncryptor.run();
    }
}