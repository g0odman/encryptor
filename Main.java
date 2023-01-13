import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

    public static void main(String[] args) throws IOException, KeyStoreException, InvalidKeyException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, IllegalBlockSizeException, BadPaddingException {
        // Load properties file
        if (args.length != 2) {
            System.out.println("Usage: HybridEncryptor [e|d] <config file> \n\te is to encrypt and d is to decrypt");
            return;
        }

        EncryptionPropertiesParser propertiesParser = new EncryptionPropertiesParser(args[1]);
        System.out.println(args[0]);
        if (args[0].startsWith("e")) {
            System.out.println("Encrypting!");
            HybridEncryptor encryptor = new HybridEncryptor(propertiesParser);
            encryptor.run();
        }
        
        else if (args[0].startsWith("d")) {
            System.out.println("Decrypting!");
            DecryptionPropertiesParser decryptionPropertiesParser = new DecryptionPropertiesParser(propertiesParser.getOutConfigFile());
            HybridDecryptor decryptor = new HybridDecryptor(decryptionPropertiesParser);
            decryptor.run();
        }
        else {
            System.out.println("AAAA");
            System.out.println("Usage: HybridEncryptor [e|d] <config file> \n\te is to encrypt and d is to decrypt");
            return;
        }
    }
}