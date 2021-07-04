import org.yaml.snakeyaml.Yaml;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Server {
    public static class Config{
        public int port;
        public String dbURL;
    }
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        InputStream inputStream = new FileInputStream("server-config.yml");
        Yaml yaml = new Yaml();
        Config config = yaml.loadAs(inputStream, Config.class);
        inputStream.close();

//         Open a database connection
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(config.dbURL);

//        getting the private key from database:
        EntityManager em = emf.createEntityManager();
        String base64PrivateKey = (String) em.createQuery("SELECT k.privateKey FROM StoredKeyPair k").getSingleResult();
        em.close();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey));
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

        try (ServerSocket serverSocket = new ServerSocket(config.port)) {
            System.out.println("server listening on port " + config.port + " ...");
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("incoming TCP syn connection...");
                new Thread(new Handler(socket,privateKey,emf.createEntityManager())).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        // Close the database connection:
        emf.close();
    }
}
