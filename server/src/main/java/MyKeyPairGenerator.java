import dto.StoredKeyPair;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class MyKeyPairGenerator {
    public static void main(String args[]) throws Exception{

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        //Initializing the KeyPairGenerator
        keyPairGen.initialize(2048);

        //Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();
        byte[] pub = pair.getPublic().getEncoded();
        byte[] pri = pair.getPrivate().getEncoded();

        //        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        System.out.println(Base64.getEncoder().encodeToString(pub));
        System.out.println(Base64.getEncoder().encodeToString(pri));

        EntityManagerFactory emf = Persistence.createEntityManagerFactory( "objectdb:./db.odb");
        EntityManager em = emf.createEntityManager();
        em.getTransaction().begin();
        em.createQuery("DELETE FROM StoredKeyPair e").executeUpdate();
        em.persist(new StoredKeyPair(Base64.getEncoder().encodeToString(pub), Base64.getEncoder().encodeToString(pri)));
        em.getTransaction().commit();
        em.close();
        emf.close();
    }
}