import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class TestRSA {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        System.out.println(key.getFormat());

        Cipher encryptCipher = Cipher.getInstance("RSA");

        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

//        String secretMessage = "Baeldung secret message";

//        byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
        byte[] secretMessageBytes = key.getEncoded();
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        System.out.println(secretMessageBytes.length);
//        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
//
//        Cipher decryptCipher = Cipher.getInstance("RSA");
//        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//
//        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
//        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
//
//        System.out.println(decryptedMessage);

    }
}
