import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class TestAES {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // for example
        SecretKey sessionKey = keyGen.generateKey();


        Cipher AESDecryptCipher = Cipher.getInstance("AES_128/OFB/NOPADDING");
        Cipher AESEncryptCipher = Cipher.getInstance("AES_128/OFB/NOPADDING");
        byte[] IV = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(IV);
        AESDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IV));
        AESEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IV));

        String msg = "hello";
        String recMes = new String(AESDecryptCipher.doFinal(AESEncryptCipher.doFinal(msg.getBytes())));
        System.out.println(recMes);
    }
}
