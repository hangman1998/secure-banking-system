import dto.*;
import lombok.SneakyThrows;
import me.gosimple.nbvcxz.Nbvcxz;
import me.gosimple.nbvcxz.scoring.Result;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.EntityManager;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Handler implements Runnable {
    private final Socket socket;
    private final PrivateKey privateKey;
    private final EntityManager em;
    private final Nbvcxz passwordChecker;
    private final MessageDigest digest;
    private final SecureRandom random;
    private ObjectInputStream reader;
    private ObjectOutput writer;


    public Handler(Socket socket, PrivateKey privateKey, EntityManager em) throws NoSuchAlgorithmException {
        this.socket = socket;
        this.privateKey = privateKey;
        this.em = em;
        passwordChecker = new Nbvcxz();
        digest = MessageDigest.getInstance("SHA-256");
        random = new SecureRandom();
        em.getMetamodel().entity(Account.class);
        em.getMetamodel().entity(Message.class);
        em.getMetamodel().entity(PartnershipQueue.class);
        em.getMetamodel().entity(User.class);
        em.getMetamodel().entity(UserAccounts.class);
    }

    private boolean keyExchange()
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
//        System.out.println("init key exchange protocol");
        BufferedInputStream rawByteReader = new BufferedInputStream(socket.getInputStream());
//            getting the session key from client (session key should be 256 bytes exactly)(block size of RSA):
        byte[] encryptedSessionKey = new byte[256];
        byte[] encryptedIV = new byte[256];
        for (int i = 0; i < 256; i++)
            encryptedSessionKey[i] = (byte) rawByteReader.read();
//        System.out.println(" ses key read was successful");
        for (int i = 0; i < 256; i++)
            encryptedIV[i] = (byte) rawByteReader.read();
//        System.out.println(" IV read was successful");
        //            decrypting the session key:
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] sessionKey = decryptCipher.doFinal(encryptedSessionKey);
        byte[] IV = decryptCipher.doFinal(encryptedIV);

//        System.out.println(Arrays.toString(sessionKey));
//        System.out.println(Arrays.toString(IV));

//            generating the cipher Reader and writer:
        Cipher AESDecryptCipher = Cipher.getInstance("AES/OFB/PKCS5PADDING");
        Cipher AESEncryptCipher = Cipher.getInstance("AES/OFB/PKCS5PADDING");
        AESDecryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new IvParameterSpec(IV));
        AESEncryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new IvParameterSpec(IV));


        OutputStream cOut = new MyCipherOutputStream(socket.getOutputStream(), AESEncryptCipher);
        InputStream cIn = new MyCipherInputStream(new BufferedInputStream(socket.getInputStream()), AESDecryptCipher);


        writer = new ObjectOutputStream(cOut);
        writer.flush();
        reader = new ObjectInputStream(cIn);


//        System.out.println("object header flushed! generating nonce");
//        authenticating the client:
//        generating a nonce:
        int nonce = random.nextInt();
        writer.writeInt(nonce);
        writer.flush();
        cOut.flush();
//        System.out.println("nonce was sent, waiting for the response...");

        return reader.readInt() == nonce + 1;
    }

    private void rejectAuthentication(String msg) throws IOException {
        writer.writeBoolean(false);
        writer.writeObject(msg);
        writer.flush();
    }

    private void acceptAuthentication(String msg) throws IOException {
        writer.writeBoolean(true);
        writer.writeObject(msg);
        writer.flush();
    }

    private long generateAccountNumber()
    {
        if ((long) em.createQuery("SELECT count(a) from Account a").getSingleResult() > 0)
        {
            long maxAccNum = (long) em.createQuery("SELECT MAX(a.accNum) from Account a").getSingleResult();
            return maxAccNum + 1 + random.nextInt(1024);
        }
        else
            return 1000000000 + 1 + random.nextInt(1024);
    }
    ////        System.out.println("in handle auth.");
////        writer.writeObject("*** welcome to the Secure Bank CLI ***\n you can use the `?l` command to view available options\n");
////        writer.flush();


    private void dashboard(String username) throws IOException, ClassNotFoundException {
        System.out.println("in " + username + " dashboard");
        boolean loop = true;
        while (loop) {
            Message msg = (Message) reader.readObject();
            switch (msg.getType()) {
                case LOGOUT -> {
                    loop = false;
                    writer.writeObject("logging out from user: " + username);
                    writer.flush();
                }
                case REQUEST_JOIN -> {
                    long accNum = msg.getAccountNum();
                    if ((long) em.createQuery("select count(u) from Account u where u.accNum = :un").setParameter("un", accNum).getSingleResult() == 0) {
                        writer.writeObject("ERROR: invalid account number!\n");
                        writer.flush();
                        break;
                    }
                    if ((long) em.createQuery("select count(q) from PartnershipQueue q where q.accNum = :an and q.username = :un").setParameter("an", accNum).setParameter("un",username).getSingleResult() != 0) {
                        writer.writeObject("ERROR: you have already requested your ownership request for this account\n");
                        writer.flush();
                        break;
                    }
                    em.getTransaction().begin();
                    em.persist(new PartnershipQueue(accNum, username));
                    em.getTransaction().commit();
                    writer.writeObject("*** your request was successfully registered ***\n");
                    writer.flush();
                }

                case ACCEPT_JOIN -> {
                    String newOwner = msg.getUsername();
                    long accNum = msg.getAccountNum();
                    IntLevel intLevel = msg.getIntLevel();
                    ConfLevel confLevel = msg.getConfLevel();
                    if ( newOwner.contains(" ") || newOwner.contains("\t") || newOwner.contains("\n")) {
                        writer.writeObject("ERROR: invalid username!\n");
                        writer.flush();
                        break;
                    }
                    if (intLevel == null ) {
                        writer.writeObject("ERROR: invalid integrity level \n");
                        writer.flush();
                        break;
                    }
                    if (confLevel == null ) {
                        writer.writeObject("ERROR: invalid confidentiality level \n");
                        writer.flush();
                        break;
                    }
                    List<Boolean> res =  em.createQuery("select u.isOwner from UserAccounts u where u.accNum = :an and u.username = :un", Boolean.class).setParameter("un", username).setParameter("an", accNum).getResultList();
                    if (res.isEmpty() || !res.get(0))
                    {
                        writer.writeObject("ERROR: you are not the first owner of this account number\n");
                        writer.flush();
                        break;
                    }
                    if ((long)em.createQuery("select count(q) from PartnershipQueue q where q.username = :un and q.accNum = :an").setParameter("un", newOwner).setParameter("an", accNum).getSingleResult() != 1)
                    {
                        writer.writeObject("ERROR: this user has not requested to take partnership in this account!\n");
                        writer.flush();
                        break;
                    }
//                    Now the accept should be processed into the system:
                    em.getTransaction().begin();
                    em.createQuery("DELETE from PartnershipQueue q where q.accNum = :an and q.username = :un").setParameter("un", newOwner).setParameter("an", accNum).executeUpdate();
                    em.persist(new UserAccounts(accNum, newOwner, false, intLevel, confLevel));
                    em.getTransaction().commit();
                    writer.writeObject("*** user: " + newOwner + " is now an owner of account: " + accNum + " ***\n" );
                    writer.flush();

                }
                case CREATE_ACCOUNT -> {
                    IntLevel intLevel = msg.getIntLevel();
                    ConfLevel confLevel = msg.getConfLevel();
                    long initialAmount = msg.getInitialAmount();
                    AccountType type = msg.getAccountType();
                    if (intLevel == null ) {
                        writer.writeObject("ERROR: invalid integrity level \n");
                        writer.flush();
                        break;
                    }
                    if (confLevel == null ) {
                        writer.writeObject("ERROR: invalid confidentiality level \n");
                        writer.flush();
                        break;
                    }
                    if (type == null ) {
                        writer.writeObject("ERROR: invalid account type\n");
                        writer.flush();
                        break;
                    }

                    if (initialAmount <= 0)
                    {
                        writer.writeObject("ERROR: account initial amount cannot be less than equal zero\n");
                        writer.flush();
                        break;
                    }
                    Account a = new Account(type,intLevel,confLevel,initialAmount, generateAccountNumber());
                    em.getTransaction().begin();
                    em.persist(a);
                    em.persist(new UserAccounts(a.getAccNum(), username,true,intLevel,confLevel));
                    em.getTransaction().commit();
                    writer.writeObject("*** a new account with account number: "+ a.getAccNum()+ " was created under your name ***\n");
                    writer.flush();
                }
                case SHOW_ACCOUNT -> {
                    if (msg.isShowAll())
                    {
                        List<Long> accs = em.createQuery("select a.accNum from UserAccounts a where a.username = :un ",Long.class).setParameter("un", username).getResultList();
                        writer.writeObject("Your Accounts:\n" + accs);
                        writer.flush();
                    }
                    else
                    {
                        long accNum = msg.getAccountNum();
                        List<UserAccounts> res =  em.createQuery("select u from UserAccounts u where u.username = :un and u.accNum = :an", UserAccounts.class)
                                .setParameter("un", username).setParameter("an", accNum)
                                .getResultList();
                        if (res.isEmpty())
                        {
                            writer.writeObject("ERROR: you are not an owner of the source account\n");
                            writer.flush();
                            break;
                        }
                        IntLevel userIntLevel = res.get(0).getIntegrity();
                        ConfLevel userConfLevel = res.get(0).getConfidentiality();


                        List<Account> accs = em.createQuery("select a from Account a where a.accNum = :acc", Account.class)
                                .setParameter("acc", accNum).getResultList();
                        assert accs.size() == 1;
                        Account acc = accs.get(0);
                        if (acc.getConfidentiality().level > userConfLevel.level || acc.getIntegrity().level < userIntLevel.level)
                        {
                            writer.writeObject("ERROR: you do not have the required permissions on this account to accomplish this task\n");
                            writer.flush();
                            break;
                        }
//                        getting owners of the account:
                        List<UserAccounts> owners = em.createQuery("select u from UserAccounts u where u.accNum = :acc",UserAccounts.class)
                                .setParameter("acc", accNum).getResultList();
//                        getting deposits and withdraws:
                        List<Transfer> transfers = em.createQuery("select t from Transfer t where t.src = :acc or t.dest = :acc order by t.date",
                                Transfer.class).setParameter("acc", accNum).getResultList();
                        StringBuilder accInfo = new StringBuilder();
                        accInfo.append(acc);
                        accInfo.append("Owners info:\n----\n");
                        for (UserAccounts o:owners) {
                            if (o.isOwner())
                                accInfo.append("* ");
                            accInfo.append(o.getUsername()).append(" integrity: ").append(o.getIntegrity().toString()).append(" confidentiality: ").append(o.getConfidentiality().toString()).append("\n");
                        }
                        accInfo.append("Last five deposits to this account:\n----\n");
                        int count =0;
                        for (Transfer t: transfers) {
                            if (t.getDest() == acc.getAccNum() && count <5)
                            {
                                count ++;
                                accInfo.append("from: " + t.getSrc() + " by: " + t.getUsername() + " at: " + t.getDate().toString() + " amount| " + t.getAmount() + "\n");
                            }
                        }

                        accInfo.append("Last five withdraws to this account:\n----\n");
                         count =0;
                        for (Transfer t: transfers) {
                            if (t.getSrc() == acc.getAccNum() && count <5)
                            {
                                count ++;
                                accInfo.append("to: " + t.getDest() + " by: " + t.getUsername() + " at: " + t.getDate().toString() + " amount| " + t.getAmount() + "\n");
                            }
                        }
                        writer.writeObject(accInfo.toString());
                        writer.flush();
                    }
                }

                case TRANSFER -> {
                    long amount = msg.getAmount();
                    long from = msg.getFromAccNum();
                    long to = msg.getToAccNum();
                    if (amount <= 0 )
                    {
                        writer.writeObject("ERROR: transfer amount cannot be less than equal zero\n");
                        writer.flush();
                        break;
                    }
                    List<Account> accs = em.createQuery("select a from Account a where a.accNum = :f", Account.class)
                            .setParameter("f", from).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR:source account number is incorrect\n");
                        writer.flush();
                        break;
                    }
                    Account sourceAccount = accs.get(0);

                    accs = em.createQuery("select a from Account a where a.accNum = :t", Account.class)
                            .setParameter("t", to).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR:destination account number is incorrect\n");
                        writer.flush();
                        break;
                    }
                    Account destAccount = accs.get(0);

                    List<UserAccounts> res =  em.createQuery("select u from UserAccounts u where u.username = :un and u.accNum = :an", UserAccounts.class)
                            .setParameter("un", username).setParameter("an", from)
                            .getResultList();
                    if (res.isEmpty())
                    {
                        writer.writeObject("ERROR: you are not an owner of the source account\n");
                        writer.flush();
                        break;
                    }
                    IntLevel userIntLevel = res.get(0).getIntegrity();
                    ConfLevel userConfLevel = res.get(0).getConfidentiality();
                    if (sourceAccount.getConfidentiality().level < userConfLevel.level || sourceAccount.getIntegrity().level > userIntLevel.level)
                    {
                        writer.writeObject("ERROR: you do not have the required permissions on this account to accomplish this task\n");
                        writer.flush();
                        break;
                    }
                    if (sourceAccount.getAmount() < amount)
                    {
                        writer.writeObject("ERROR: the specified transfer amount is not present in the source account\n");
                        writer.flush();
                        break;
                    }
//                    all checks have passed, so the task must no be processed:
                    em.getTransaction().begin();
                    sourceAccount.setAmount(sourceAccount.getAmount() - amount);
                    destAccount.setAmount(destAccount.getAmount() + amount);
                    em.persist(new Transfer(username, from, to ,amount, new Date()));
                    em.getTransaction().commit();
                    writer.writeObject("*** " + amount + " rials was successfully transferred from " + from + " to " + to + " ***\n");
                    writer.flush();
                }
            }
        }



        //        em.getTransaction().begin();
//        int deletedCount = em.createQuery("DELETE FROM Object").executeUpdate();
//        em.getTransaction().commit();
//        System.out.println(deletedCount);
//        // Find the number of Point objects in the database:
//        Query q1 = em.createQuery("SELECT COUNT(p) FROM Point p");
//        System.out.println("Total Points: " + q1.getSingleResult());
//
//        // Find the average X value:
//        Query q2 = em.createQuery("SELECT AVG(p.x) FROM Point p");
//        System.out.println("Average X: " + q2.getSingleResult());
//
//        // Retrieve all the Point objects from the database:
//        TypedQuery<Point> query =
//                em.createQuery("SELECT p FROM Point p", Point.class);
//        List<Point> results = query.getResultList();
//        for (Point p : results) {
//            System.out.println(p);
//        }

    }

    @SneakyThrows
    public void run() {
        try {
//            key exchange protocol:
            if (keyExchange()) {
                byte[] passwordHash;
                byte[] salt = new byte[32];
                ByteArrayOutputStream byteCombiner = new ByteArrayOutputStream();
                boolean loop = true;
                while (loop) {
                    Message msg = (Message) reader.readObject();
                    switch (msg.getType()) {
                        case SIGN_UP -> {
                            String username = msg.getUsername();
                            String pass = msg.getPassword();
                            if (pass.contains(" ") || pass.contains("\t") || pass.contains("\n") || username.contains(" ") || username.contains("\t") || username.contains("\n")) {
                                rejectAuthentication("ERROR: bad input! SUGGESTION: use the authorised client program\n");
                                continue;
                            }
                            if ((long) em.createQuery("select count(u) from User u where u.username = :un").setParameter("un", username).getSingleResult() != 0) {
                                rejectAuthentication("ERROR: duplicate username SUGGESTION: please choose another username\n");
                                break;
                            }
                            Result result = passwordChecker.estimate(pass);
                            if (!result.isMinimumEntropyMet()) {
                                rejectAuthentication("ERROR: password has not met the minimum security requirements\n" +
                                        "WARNING: " + result.getFeedback().getWarning() + "\n" +
                                        "SUGGESTION: " + result.getFeedback().getSuggestion() + "\n");
                                break;
                            }
//                    sign up now should be processed:
                            random.nextBytes(salt);
                            byteCombiner.write(pass.getBytes(StandardCharsets.UTF_8));
                            byteCombiner.write(salt);
                            passwordHash = digest.digest(byteCombiner.toByteArray());
                            byteCombiner.reset();
                            em.getTransaction().begin();
                            em.persist(new User(username, passwordHash, salt));
                            em.getTransaction().commit();
                            acceptAuthentication("*** sign up was successful; you are now in your dashboard ***\n");
                            dashboard(username);
                        }
                        case LOGIN -> {
                            String username = msg.getUsername();
                            String pass = msg.getPassword();
                            if (pass.contains(" ") || pass.contains("\t") || pass.contains("\n") || username.contains(" ") || username.contains("\t") || username.contains("\n")) {
                                rejectAuthentication("ERROR: bad input! SUGGESTION: use the authorised client program\n");
                                continue;
                            }
                            if ((long) em.createQuery("select  count(u) from User u where u.username = :un").setParameter("un", username).getSingleResult() != 1) {
                                rejectAuthentication("ERROR: username password do not match. SUGGESTION: please check your input\n");
                                break;
                            }
                            salt = em.createQuery("select u.salt from User u where u.username = :un", byte[].class).setParameter("un", username).getSingleResult();
                            byte[] passwordHashInDB = em.createQuery("select u.passwordHash from User u where u.username = :un", byte[].class).setParameter("un", username).getSingleResult();
                            byteCombiner.write(pass.getBytes(StandardCharsets.UTF_8));
                            byteCombiner.write(salt);
                            passwordHash = digest.digest(byteCombiner.toByteArray());
                            byteCombiner.reset();
                            if (!Arrays.equals(passwordHashInDB, passwordHash)) {
                                rejectAuthentication("ERROR: username password do not match. SUGGESTION: please check your input\n");
                                break;
                            }
                            acceptAuthentication("*** login was successful; you are now in your dashboard ***\n");
                            dashboard(username);
                        }
                        case TERMINATE -> loop = false;
                    }
                }
                byteCombiner.close();
            }


        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | IOException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) {
            System.out.println("Error in key exchange");
            e.printStackTrace();
        }
        reader.close();
        writer.close();
        socket.close();
        em.close();
    }
}
