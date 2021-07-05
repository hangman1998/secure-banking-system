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
import java.util.*;
import java.util.concurrent.TimeUnit;

public class Handler implements Runnable {
    private final Socket socket;
    private final PrivateKey privateKey;
    private final EntityManager em;
    private final Nbvcxz passwordChecker;
    private final MessageDigest digest;
    private final SecureRandom random;
    private ObjectInputStream reader;
    private ObjectOutput writer;
    private final int numOfTries;
    private final int banTime;


    public Handler(Socket socket, PrivateKey privateKey, EntityManager em, int numOfTries, int banTime) throws NoSuchAlgorithmException {
        this.socket = socket;
        this.privateKey = privateKey;
        this.em = em;
        passwordChecker = new Nbvcxz();
        digest = MessageDigest.getInstance("SHA-256");
        random = new SecureRandom();
        em.getMetamodel().entity(Account.class);
        em.getMetamodel().entity(Ban.class);
        em.getMetamodel().entity(Log.class);
        em.getMetamodel().entity(PartnershipQueue.class);
        em.getMetamodel().entity(Session.class);
        em.getMetamodel().entity(Transfer.class);
        em.getMetamodel().entity(User.class);
        em.getMetamodel().entity(UserAccounts.class);
        this.banTime = banTime;
        this.numOfTries= numOfTries;
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


    private void dashboard(Session session) throws IOException, ClassNotFoundException, CloneNotSupportedException {
        String username = session.getUsername();
        System.out.println("in " + username + " dashboard");
        boolean loop = true;
        while (loop) {
            Message msg = (Message) reader.readObject();
            switch (msg.getType()) {
                case LOGOUT -> {
                    loop = false;

                    em.getTransaction().begin();
                    session.setEndDate(new Date());
                    em.getTransaction().commit();

                    Log log = new Log(msg, null);
                    log.finishedSession = session;
                    addLog(log);

                    writer.writeObject("logging out from user: " + username);
                    writer.flush();
                }
                case REQUEST_JOIN -> {
                    long accNum = msg.getAccountNum();
                    if ((long) em.createQuery("select count(u) from Account u where u.accNum = :un").setParameter("un", accNum).getSingleResult() == 0) {
                        writer.writeObject("ERROR: invalid account number!\n");
                        writer.flush();
                        Log log = new Log(msg, FailReason.INVALID_ACCOUNT_NUM);
                        addLogWithSession(log, session);
                        break;
                    }
                    if ((long) em.createQuery("select count(q) from PartnershipQueue q where q.accNum = :an and q.username = :un").setParameter("an", accNum).setParameter("un",username).getSingleResult() != 0) {
                        writer.writeObject("ERROR: you have already requested your ownership request for this account\n");
                        writer.flush();
                        Log log = new Log(msg, FailReason.DUPLICATE_JOIN_REQUEST);
                        addLogWithSession(log, session);
                        break;
                    }

                    if ((long) em.createQuery("select count(q) from UserAccounts q where q.accNum = :an and q.username = :un ").setParameter("an", accNum).setParameter("un",username).getSingleResult() != 0) {
                        writer.writeObject("ERROR: you are yourself an owner of this account!\n");
                        writer.flush();
                        Log log = new Log(msg, FailReason.ALREADY_AN_OWNER);
                        addLogWithSession(log, session);
                        break;
                    }

                    PartnershipQueue newRequest = new PartnershipQueue(accNum, username);
                    em.getTransaction().begin();
                    em.persist(newRequest);
                    em.getTransaction().commit();
                    writer.writeObject("*** your request was successfully registered ***\n");
                    writer.flush();
                    Log log = new Log(msg, null);
                    log.createdRequest = newRequest;
                    addLogWithSession(log, session);
                }

                case ACCEPT_JOIN -> {
                    String newOwner = msg.getUsername();
                    long accNum = msg.getAccountNum();
                    IntLevel intLevel = msg.getIntLevel();
                    ConfLevel confLevel = msg.getConfLevel();
                    if ( newOwner.contains(" ") || newOwner.contains("\t") || newOwner.contains("\n")) {
                        writer.writeObject("ERROR: invalid username!\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NON_EXISTENT_USERNAME);
                        addLogWithSession(log, session);

                        break;
                    }
                    if (intLevel == null ) {
                        writer.writeObject("ERROR: invalid integrity level \n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_INT_LEVEL);
                        addLogWithSession(log, session);

                        break;
                    }
                    if (confLevel == null ) {
                        writer.writeObject("ERROR: invalid confidentiality level \n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_CONF_LEVEL);
                        addLogWithSession(log, session);

                        break;
                    }
                    List<Boolean> res =  em.createQuery("select u.isOwner from UserAccounts u where u.accNum = :an and u.username = :un", Boolean.class).setParameter("un", username).setParameter("an", accNum).getResultList();
                    if (res.isEmpty() || !res.get(0))
                    {
                        writer.writeObject("ERROR: you are not the first owner of this account number\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NOT_OWNER);
                        addLogWithSession(log, session);

                        break;
                    }
                    if ((long)em.createQuery("select count(q) from PartnershipQueue q where q.username = :un and q.accNum = :an").setParameter("un", newOwner).setParameter("an", accNum).getSingleResult() != 1)
                    {
                        writer.writeObject("ERROR: this user has not requested to take partnership in this account!\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NON_EXISTENT_REQUEST);
                        addLogWithSession(log, session);

                        break;
                    }
                    if ((long)em.createQuery("select count(q) from PartnershipQueue q where q.username = :un and q.accNum = :an and q.gotProcessed = true ").setParameter("un", newOwner).setParameter("an", accNum).getSingleResult() > 0)
                    {
                        writer.writeObject("ERROR: you have already accepted this user join request!\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NON_EXISTENT_REQUEST);
                        addLogWithSession(log, session);

                        break;
                    }
//                    Now the accept should be processed into the system:

                    PartnershipQueue acceptedrequest = em.createQuery("select  q from PartnershipQueue q where q.accNum = :an and q.username = :un", PartnershipQueue.class)
                            .setParameter("un", newOwner).setParameter("an", accNum).getSingleResult();
                    UserAccounts newUserAccount = new UserAccounts(accNum, newOwner, false, intLevel, confLevel);



                    em.getTransaction().begin();
//                    em.createQuery("DELETE from PartnershipQueue q where q.accNum = :an and q.username = :un").setParameter("un", newOwner).setParameter("an", accNum).executeUpdate();
                    acceptedrequest.setGotProcessed(true);
                    em.persist(newUserAccount);
                    em.getTransaction().commit();
                    writer.writeObject("*** user: " + newOwner + " is now an owner of account: " + accNum + " ***\n" );
                    writer.flush();

                    Log log = new Log(msg, null);
                    log.acceptedRequest = acceptedrequest;
                    log.createdUserAccount = newUserAccount;
                    addLogWithSession(log, session);

                }
                case CREATE_ACCOUNT -> {
                    IntLevel intLevel = msg.getIntLevel();
                    ConfLevel confLevel = msg.getConfLevel();
                    long initialAmount = msg.getInitialAmount();
                    AccountType type = msg.getAccountType();
                    if (intLevel == null ) {
                        writer.writeObject("ERROR: invalid integrity level \n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_INT_LEVEL);
                        addLogWithSession(log, session);

                        break;
                    }
                    if (confLevel == null ) {
                        writer.writeObject("ERROR: invalid confidentiality level \n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_CONF_LEVEL);
                        addLogWithSession(log, session);

                        break;
                    }
                    if (type == null ) {
                        writer.writeObject("ERROR: invalid account type\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_ACC_TYPE);
                        addLogWithSession(log, session);

                        break;
                    }

                    if (initialAmount <= 0)
                    {
                        writer.writeObject("ERROR: account initial amount cannot be less than equal zero\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NEGATIVE_AMOUNT);
                        addLogWithSession(log, session);

                        break;
                    }
                    Account a = new Account(type,intLevel,confLevel,initialAmount, generateAccountNumber());
                    UserAccounts u = new UserAccounts(a.getAccNum(), username,true,intLevel,confLevel);


                    em.getTransaction().begin();
                    em.persist(a);
                    em.persist(u);
                    em.getTransaction().commit();
                    writer.writeObject("*** a new account with account number: "+ a.getAccNum()+ " was created under your name ***\n");
                    writer.flush();

                    Log log = new Log(msg, null);
                    log.createdAccount = a;
                    log.createdUserAccount = u;
                    addLogWithSession(log, session);

                }

                case SHOW_ACCOUNT -> {
                    if (msg.isShowAll())
                    {
                        List<Long> accs = em.createQuery("select a.accNum from UserAccounts a where a.username = :un ",Long.class).setParameter("un", username).getResultList();
                        writer.writeObject("Your Accounts:\n" + accs);
                        writer.flush();

                        Log log = new Log(msg, null);
                        log.showedAccounts = accs;
                        addLogWithSession(log, session);

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

                            Log log = new Log(msg, FailReason.NOT_OWNER);
                            addLogWithSession(log, session);

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

                            Log log = new Log(msg, FailReason.NO_READ_RIGHT);
                            log.accountIntLevel = acc.getIntegrity();
                            log.userAccountIntLevel = userIntLevel;
                            log.accountConfLevel = acc.getConfidentiality();
                            log.userAccountConfLevel = userConfLevel;
                            addLogWithSession(log, session);

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

                        Log log = new Log(msg, null);
                        log.accountIntLevel = acc.getIntegrity();
                        log.userAccountIntLevel = userIntLevel;
                        log.accountConfLevel = acc.getConfidentiality();
                        log.userAccountConfLevel = userConfLevel;
                        log.showedAccountAmount = acc.getAmount();

                        addLogWithSession(log, session);

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

                        Log log = new Log(msg, FailReason.NEGATIVE_AMOUNT);
                        addLogWithSession(log, session);

                        break;
                    }
                    List<Account> accs = em.createQuery("select a from Account a where a.accNum = :f", Account.class)
                            .setParameter("f", from).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR:source account number is incorrect\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_ACCOUNT_NUM);
                        addLogWithSession(log, session);

                        break;
                    }
                    Account sourceAccount = accs.get(0);

                    accs = em.createQuery("select a from Account a where a.accNum = :t", Account.class)
                            .setParameter("t", to).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR:destination account number is incorrect\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_ACCOUNT_NUM);
                        addLogWithSession(log, session);

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

                        Log log = new Log(msg, FailReason.NOT_OWNER);
                        addLogWithSession(log, session);

                        break;
                    }
                    IntLevel userIntLevel = res.get(0).getIntegrity();
                    ConfLevel userConfLevel = res.get(0).getConfidentiality();
                    if (sourceAccount.getConfidentiality().level < userConfLevel.level || sourceAccount.getIntegrity().level > userIntLevel.level)
                    {
                        writer.writeObject("ERROR: you do not have the required permissions on this account to accomplish this task\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NO_WRITE_RIGHT);
                        log.accountIntLevel = sourceAccount.getIntegrity();
                        log.userAccountIntLevel = userIntLevel;
                        log.accountConfLevel = sourceAccount.getConfidentiality();
                        log.userAccountConfLevel = userConfLevel;
                        addLogWithSession(log, session);

                        break;
                    }
                    if (sourceAccount.getAmount() < amount)
                    {
                        writer.writeObject("ERROR: the specified transfer amount is not present in the source account\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INSUFFICIENT_FUNDS);
                        addLogWithSession(log, session);

                        break;
                    }
//                    all checks have passed, so the task must no be processed:
                    Transfer newTransfer = new Transfer(username, from, to ,amount, new Date());

                    em.getTransaction().begin();
                    sourceAccount.setAmount(sourceAccount.getAmount() - amount);
                    destAccount.setAmount(destAccount.getAmount() + amount);
                    em.persist(newTransfer);
                    em.getTransaction().commit();
                    writer.writeObject("*** " + amount + " rials was successfully transferred from " + from + " to " + to + " ***\n");
                    writer.flush();

                    Log log = new Log(msg, null);
                    log.accountIntLevel = sourceAccount.getIntegrity();
                    log.userAccountIntLevel = userIntLevel;
                    log.accountConfLevel = sourceAccount.getConfidentiality();
                    log.userAccountConfLevel = userConfLevel;

                    log.srcOriginalAmount = sourceAccount.getAmount();
                    log.srcUpdatedAmount = sourceAccount.getAmount() - amount;
                    log.destOriginalAmount = destAccount.getAmount();
                    log.destUpdatedAmount = destAccount.getAmount() + amount;
                    log.createdTransfer = newTransfer;
                    addLogWithSession(log, session);
                }

                case WITHDRAW -> {
                    long amount = msg.getAmount();
                    long from = msg.getFromAccNum();
                    if (amount <= 0 )
                    {
                        writer.writeObject("ERROR: withdraw amount cannot be less than equal zero\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NEGATIVE_AMOUNT);
                        addLogWithSession(log, session);

                        break;
                    }
                    List<Account> accs = em.createQuery("select a from Account a where a.accNum = :f", Account.class)
                            .setParameter("f", from).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR: account number is incorrect\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_ACCOUNT_NUM);
                        addLogWithSession(log, session);

                        break;
                    }
                    Account sourceAccount = accs.get(0);

                    List<UserAccounts> res =  em.createQuery("select u from UserAccounts u where u.username = :un and u.accNum = :an", UserAccounts.class)
                            .setParameter("un", username).setParameter("an", from)
                            .getResultList();
                    if (res.isEmpty())
                    {
                        writer.writeObject("ERROR: you are not an owner of the this account\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NOT_OWNER);
                        addLogWithSession(log, session);

                        break;
                    }
                    IntLevel userIntLevel = res.get(0).getIntegrity();
                    ConfLevel userConfLevel = res.get(0).getConfidentiality();
                    if (sourceAccount.getConfidentiality().level < userConfLevel.level || sourceAccount.getIntegrity().level > userIntLevel.level)
                    {
                        writer.writeObject("ERROR: you do not have the required permissions on this account to accomplish this task\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NO_WRITE_RIGHT);
                        log.accountIntLevel = sourceAccount.getIntegrity();
                        log.userAccountIntLevel = userIntLevel;
                        log.accountConfLevel = sourceAccount.getConfidentiality();
                        log.userAccountConfLevel = userConfLevel;
                        addLogWithSession(log, session);

                        break;
                    }
                    if (sourceAccount.getAmount() < amount)
                    {
                        writer.writeObject("ERROR: the specified withdraw amount is not present in the account\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INSUFFICIENT_FUNDS);
                        addLogWithSession(log, session);

                        break;
                    }
//                    all checks have passed, so the task must no be processed:
                    Transfer newTransfer = new Transfer(username, from, -1 ,amount, new Date());

                    em.getTransaction().begin();
                    sourceAccount.setAmount(sourceAccount.getAmount() - amount);
                    em.persist(newTransfer);
                    em.getTransaction().commit();
                    writer.writeObject("*** " + amount + " rials was successfully withdrawed from " + from + " ***\n");
                    writer.flush();

                    Log log = new Log(msg, null);
                    log.accountIntLevel = sourceAccount.getIntegrity();
                    log.userAccountIntLevel = userIntLevel;
                    log.accountConfLevel = sourceAccount.getConfidentiality();
                    log.userAccountConfLevel = userConfLevel;

                    log.srcOriginalAmount = sourceAccount.getAmount();
                    log.srcUpdatedAmount = sourceAccount.getAmount() - amount;
                    log.createdTransfer = newTransfer;
                    addLogWithSession(log, session);
                }

                case DEPOSIT -> {
                    long amount = msg.getAmount();
                    long to = msg.getToAccNum();
                    if (amount <= 0 )
                    {
                        writer.writeObject("ERROR: deposit amount cannot be less than equal zero\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.NEGATIVE_AMOUNT);
//                        log.negativeAmount = true;
                        addLogWithSession(log, session);

                        break;
                    }
                    List<Account> accs = em.createQuery("select a from Account a where a.accNum = :t", Account.class)
                            .setParameter("t", to).getResultList();
                    if (accs.isEmpty())
                    {
                        writer.writeObject("ERROR: account number is incorrect\n");
                        writer.flush();

                        Log log = new Log(msg, FailReason.INVALID_ACCOUNT_NUM);
//                        log.invalidAccountNum = true;
                        addLogWithSession(log, session);

                        break;
                    }
                    Account destAccount = accs.get(0);
//                    all checks have passed, so the task must no be processed:

                    Transfer newTransfer = new Transfer(username, -1, to ,amount, new Date());

                    em.getTransaction().begin();
                    destAccount.setAmount(destAccount.getAmount() + amount);
                    em.persist(newTransfer);
                    em.getTransaction().commit();
                    writer.writeObject("*** " + amount + " rials was successfully deposited to " + to + " ***\n");
                    writer.flush();

                    Log log = new Log(msg, null);
                    log.destOriginalAmount = destAccount.getAmount();
                    log.destUpdatedAmount = destAccount.getAmount() + amount;
                    log.createdTransfer = newTransfer;
                    addLogWithSession(log, session);
                }

            }
        }

    }

    private void addLog(Log log)
    {
        log.port = socket.getPort();
        log.ip = socket.getInetAddress().getHostAddress();
        log.msg.destroyPassword();
        em.getTransaction().begin();
        em.persist(log.msg);
        em.persist(log);
        em.getTransaction().commit();
    }

    private void addLogWithSession(Log log, Session session)
    {
        log.port = socket.getPort();
        log.ip = socket.getInetAddress().getHostAddress();
        log.activeSession = session;
        log.msg.destroyPassword();
        em.getTransaction().begin();
        em.persist(log.msg);
        em.persist(log);
        em.getTransaction().commit();
    }

    @SneakyThrows
    public void run() {
        try {
//            key exchange protocol:
            if (keyExchange()) {
                byte[] passwordHash;
                byte[] salt;
                ByteArrayOutputStream byteCombiner = new ByteArrayOutputStream();
                boolean loop = true;
                Map<String, Integer> wrongPasswordCounter = new HashMap<>();

                while (loop) {
                    Message msg = (Message) reader.readObject();
                    switch (msg.getType()) {
                        case SIGN_UP -> {
                            String username = msg.getUsername();
                            String pass = msg.getPassword();
                            if (pass.contains(" ") || pass.contains("\t") || pass.contains("\n") || username.contains(" ") || username.contains("\t") || username.contains("\n")) {
                                rejectAuthentication("ERROR: bad input! SUGGESTION: use the authorised client program\n");
                                Log log = new Log(msg, FailReason.BAD_INPUT);
//                                log.badInput = true;
                                addLog(log);
                                continue;
                            }
                            if ((long) em.createQuery("select count(u) from User u where u.username = :un").setParameter("un", username).getSingleResult() != 0) {
                                rejectAuthentication("ERROR: duplicate username SUGGESTION: please choose another username\n");
                                Log log = new Log(msg, FailReason.DUP_USERNAME);
//                                log.dupUsername = true;
                                addLog(log);
                                break;
                            }
                            Result result = passwordChecker.estimate(pass);
                            if (!result.isMinimumEntropyMet()) {
                                rejectAuthentication("ERROR: password has not met the minimum security requirements\n" +
                                        "WARNING: " + result.getFeedback().getWarning() + "\n" +
                                        "SUGGESTION: " + result.getFeedback().getSuggestion() + "\n");
                                Log log = new Log(msg, FailReason.WEAK_PASS);
//                                log.weakPass = true;
                                addLog(log);
                                break;
                            }
//                    sign up now should be processed:
                            salt = new byte[32];
                            random.nextBytes(salt);
                            byteCombiner.write(pass.getBytes(StandardCharsets.UTF_8));
                            byteCombiner.write(salt);
                            passwordHash = digest.digest(byteCombiner.toByteArray());
                            byteCombiner.reset();
                            User newUser = new User(username, passwordHash, salt);
                            em.getTransaction().begin();
                            em.persist(newUser);
                            em.getTransaction().commit();
                            Session newSession = new Session(username, socket);
                            em.getTransaction().begin();
                            em.persist(newSession);
                            em.getTransaction().commit();

                            Log log = new Log(msg, null);
                            log.createdUser = newUser;
                            log.createdSession = newSession;
                            addLog(log);

                            acceptAuthentication("*** sign up was successful; you are now in your dashboard ***\n");
                            dashboard(newSession);
                        }
                        case LOGIN -> {
                            String username = msg.getUsername();
                            String pass = msg.getPassword();
                            if (pass.contains(" ") || pass.contains("\t") || pass.contains("\n") || username.contains(" ") || username.contains("\t") || username.contains("\n")) {
                                rejectAuthentication("ERROR: bad input! SUGGESTION: use the authorised client program\n");
                                Log log = new Log(msg, FailReason.BAD_INPUT);
//                                log.badInput = true;
                                addLog(log);
                                continue;
                            }
                            if ((long) em.createQuery("select  count(u) from User u where u.username = :un").setParameter("un", username).getSingleResult() != 1) {
                                rejectAuthentication("ERROR: username password do not match. SUGGESTION: please check your input\n");
                                Log log = new Log(msg, FailReason.NON_EXISTENT_USERNAME);
//                                log.nonExistentUsername = true;
                                addLog(log);
                                break;
                            }
//                            check if the user is in the ban list:
                            Date latestBanDate =  em.createQuery("select  max(b.date) from Ban b where b.username = :un", Date.class).setParameter("un", username).getSingleResult();
                            if (latestBanDate != null)
                            {
                                long diffInSeconds = TimeUnit.MILLISECONDS.toSeconds( (new Date()).getTime() - latestBanDate.getTime());
                                if ( diffInSeconds < banTime)
                                {
                                    rejectAuthentication("ERROR: system has banned your account. SUGGESTION: please wait" +   (banTime - diffInSeconds) + " seconds and try again\n");
                                    Log log = new Log(msg, FailReason.BAN_USER);
//                                    log.banUser = true;
                                    addLog(log);
                                    break;
                                }
                            }

                            salt = em.createQuery("select u.salt from User u where u.username = :un", byte[].class).setParameter("un", username).getSingleResult();
                            byte[] passwordHashInDB = em.createQuery("select u.passwordHash from User u where u.username = :un", byte[].class).setParameter("un", username).getSingleResult();
                            byteCombiner.write(pass.getBytes(StandardCharsets.UTF_8));
                            byteCombiner.write(salt);
                            passwordHash = digest.digest(byteCombiner.toByteArray());
                            byteCombiner.reset();
                            if (!Arrays.equals(passwordHashInDB, passwordHash)) {
                                rejectAuthentication("ERROR: username password do not match. SUGGESTION: please check your input\n");
                                Log log = new Log(msg, FailReason.WRONG_PASS);
//                                log.wrongPass = true;
                                addLog(log);
                                wrongPasswordCounter.put(username, 1 + wrongPasswordCounter.getOrDefault(username, 0) );

//                                adding user to the ban list
                                if (wrongPasswordCounter.get(username) % numOfTries == 0)
                                {
                                    em.getTransaction().begin();
                                    em.persist( new Ban(username));
                                    em.getTransaction().commit();
                                }
                                break;
                            }
//                            reset the counter in case of successful login:
                            wrongPasswordCounter.put(username, 0);
                            Session newSession = new Session(username, socket);
                            em.getTransaction().begin();
                            em.persist(newSession);
                            em.getTransaction().commit();

                            Log log = new Log(msg, null);
                            log.createdSession = newSession;
                            addLog(log);
                            acceptAuthentication("*** login was successful; you are now in your dashboard ***\n");
                            dashboard(newSession);
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