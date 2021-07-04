import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class TestOutputStream {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, new SecureRandom(new byte[2])); // for example
        SecretKey sessionKey = keyGen.generateKey();
        byte[] iv = new byte[16];

        Cipher e = Cipher.getInstance("AES/OFB/PKCS5PADDING");
        e.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
//        e.init(Cipher.ENCRYPT_MODE, sessionKey);

        Cipher d = Cipher.getInstance("AES/OFB/PKCS5PADDING");
        d.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
//        d.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] msg = new byte[74];
        for (int i=0;i<74;i++)
            msg[i] = 120;
        byte[] decMsg = new byte[74];

        ByteArrayOutputStream buf =  new ByteArrayOutputStream();

//        recyclebin.SecureOutputStream out = new recyclebin.SecureOutputStream(buf, e);
        MyCipherOutputStream out = new MyCipherOutputStream(buf, e);
        out.write(msg);
        out.flush();
//        recyclebin.SecureInputStream in = new recyclebin.SecureInputStream(new ByteArrayInputStream(buf.toByteArray()), d);
        MyCipherInputStream in = new MyCipherInputStream(new ByteArrayInputStream(buf.toByteArray()), d);
        in.read(decMsg);
        System.out.println(Arrays.toString(decMsg));
    }

}
