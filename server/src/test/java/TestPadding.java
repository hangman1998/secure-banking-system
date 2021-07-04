import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

public class TestPadding {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, new SecureRandom(new byte[2])); // for example
        SecretKey sessionKey = keyGen.generateKey();


//        Set<String> algs = new TreeSet<>();
//        for (Provider provider : Security.getProviders()) {
//            provider.getServices().stream()
//                    .filter(s -> "Cipher".equals(s.getType()))
//                    .map(Provider.Service::getAlgorithm)
//                    .forEach(algs::add);
//        }
//        algs.forEach(System.out::println);


        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

        byte[] m = new byte[15];
        for (int i=0;i<15;i++)
        {
            m[i] = 100;
        }
//        m[15] = 1;
        byte[] em = cipher.doFinal(m);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] dm = cipher.doFinal(em);
        System.out.println(Arrays.toString(dm));
        System.out.println(Arrays.toString(em));
//        Cipher AESEncryptCipher = Cipher.getInstance("AES_128/OFB/NOPADDING");
//        byte[] IV = new byte[16];
//        SecureRandom sr = new SecureRandom();
//        sr.nextBytes(IV);
//        AESDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IV));
//        AESEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IV));
//
//        String msg = "hello";
//        String recMes = new String(AESDecryptCipher.doFinal(AESEncryptCipher.doFinal(msg.getBytes())));
//        System.out.println(recMes);


    }



    }
