import asg.cliche.*;
import dto.AccountType;
import dto.ConfLevel;
import dto.IntLevel;
import dto.Message;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class Client {
    public static class Config {
        public String ip;
        public int port;
        public String serverPublicKey;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Yaml yaml = new Yaml();
        InputStream configFile = new FileInputStream("client-config.yml");
        Config config = yaml.loadAs(configFile, Config.class);
        configFile.close();
        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(config.serverPublicKey)));

        try {

            Socket socket = new Socket(config.ip, config.port);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

//            generating session key and IV:
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();

            SecureRandom random = new SecureRandom();
            byte[] IV = new byte[16];
            random.nextBytes(IV);

//            sending session key and IV with the public key of server
            byte[] encryptedSessionKey = encryptCipher.doFinal(sessionKey.getEncoded());
            byte[] encryptedIV = encryptCipher.doFinal(IV);

            socket.getOutputStream().write(encryptedSessionKey);
            socket.getOutputStream().write(encryptedIV);
            socket.getOutputStream().flush();

//            System.out.println(Arrays.toString(sessionKey.getEncoded()));
//            System.out.println(Arrays.toString(IV));


//            generating reader and writer Object IO streams:
            Cipher AESDecryptCipher = Cipher.getInstance("AES/OFB/PKCS5PADDING");
            Cipher AESEncryptCipher = Cipher.getInstance("AES/OFB/PKCS5PADDING");
            AESDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IV));
            AESEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IV));

            OutputStream cOut = new MyCipherOutputStream(socket.getOutputStream(), AESEncryptCipher);
            InputStream cIn = new MyCipherInputStream(new BufferedInputStream(socket.getInputStream()), AESDecryptCipher);

            ObjectInputStream reader = new ObjectInputStream(cIn);
            ObjectOutputStream writer = new ObjectOutputStream(cOut);
            writer.flush();


//            completing the key exchange protocol (responding to the nonce sent from the server):
//            System.out.println("object header flushed! waiting for the nonce from the server");
            int nonce = reader.readInt();
//            System.out.println("nonce " + nonce);
            writer.writeInt(nonce + 1);
            writer.flush();
            cOut.flush();
//            System.out.println("nonce + 1 was sent to server");


//            waiting for the welcome message:
//            System.out.print((String) reader.readObject());

//            creating the main loop of the client:
            ShellFactory.createConsoleShell("client", "Secure Banking Client CLI Application (use ?l to see available commands)", new CLI(reader, writer)).commandLoop();

            writer.writeObject(Message.terminateMsgOf());
            writer.flush();

            writer.close();
            reader.close();
            socket.close();


        } catch (UnknownHostException ex) {
            System.out.println("Server not found: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O Error: " + ex.getMessage());
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
            System.out.println("Error in Ciphers: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public static class Dashboard
    {
        ObjectInputStream reader;
        ObjectOutputStream writer;

        public Dashboard(ObjectInputStream reader, ObjectOutputStream writer) {
            this.reader = reader;
            this.writer = writer;
        }
//        VeryTrusted("vt"),
//        Trusted("t"),
//        SlightlyTrusted("st"),
//        Untrusted("ut");

//        TopSecret("tp"),
//        Secret("s"),
//        Confidential("c"),
//        Unclassified("uc");

//        SHORT_TERM_SAVING_ACCOUNT("st"),
//        LONG_TERM_SAVING_ACCOUNT("lt"),
//        CURRENT_ACCOUNT("c"),
//        INTEREST_FREE_DEPOSIT_ACCOUNT("d");
        @Command
        public String accept(@Param(name = "account number") long accNum, @Param(name = "username") String username, @Param(name = "integrity level of the new owner", description =
        "`vt` for very-trusted, `t` for trusted, `st` for slightly trusted and `ut` for untrusted") String intLevel,@Param(name = "confidentiality level of the new owner", description =
                "`ts` for top-secret, `s` for secret, `c` for confidential and `uc` for unclasssified ") String confLevel) throws IOException, ClassNotFoundException {

            writer.writeObject(Message.acceptMsgOf(accNum, username, IntLevel.valueOfLabel(intLevel),ConfLevel.valueOfLabel(confLevel)));
            writer.flush();
            return (String) reader.readObject();
        }

        @Command
        public String create(@Param(name = "account type of the new account", description = "`st` for short-term-saving-account, `lt` for long-term-saving-account, `c` for current-account and `d` for interest-free-deposit-account") String accountType,@Param(name = "account opening money") long initialAmount, @Param(name = "integrity level of the new account", description =
                "`vt` for very-trusted, `t` for trusted, `st` for slightly trusted and `ut` for untrusted" )String intLevel,@Param(name = "confidentiality level of the new owner", description =
                "`ts` for top-secret, `s` for secret, `c` for confidential and `uc` for unclasssified ")  String confLevel) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.createMsgOf(AccountType.valueOfLabel(accountType), initialAmount, IntLevel.valueOfLabel(intLevel),ConfLevel.valueOfLabel(confLevel)));
            writer.flush();
            return (String) reader.readObject();
        }

//      for now lets disable these two:

//        @Command
//        public String deposit(long fromAccNum, long toAccNum, long amount ) throws IOException, ClassNotFoundException {
//            writer.writeObject(Message.depositMsgOf(fromAccNum, toAccNum, amount));
//            writer.flush();
//            return (String) reader.readObject();
//        }
//
//        @Command
//        public String withdraw(long fromAccNum, long toAccNum, long amount ) throws IOException, ClassNotFoundException {
//            writer.writeObject(Message.withdrawMsgOf(fromAccNum, toAccNum, amount));
//            writer.flush();
//            return (String) reader.readObject();
//        }

        @Command
        public String transfer( @Param(name = "source account") long fromAccNum,@Param(name = "dest account") long toAccNum, @Param(name = "amount") long amount ) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.transferMsgOf(fromAccNum, toAccNum, amount));
            writer.flush();
            return (String) reader.readObject();
        }

        @Command
        public String join(long accountNum ) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.joinMsgOf(accountNum));
            writer.flush();
            return (String) reader.readObject();
        }

        @Command
        public String showAccount(long accountNum ) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.showMsgOf(accountNum, false));
            writer.flush();
            return (String) reader.readObject();
        }

        @Command
        public String showMyAccounts() throws IOException, ClassNotFoundException {
            writer.writeObject(Message.showMsgOf(0, true));
            writer.flush();
            return (String) reader.readObject();
        }
    }

    public static class CLI implements ShellDependent {
        ObjectInputStream reader;
        ObjectOutputStream writer;
        // The shell which runs us. Needed to create subshells.
        private Shell shell;

        public CLI(ObjectInputStream reader, ObjectOutputStream writer) {
            this.reader = reader;
            this.writer = writer;
        }

        @Command
        public String signup(String username, String password) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.signupMsgOf(username, password));
            writer.flush();
            if (reader.readBoolean())
            {
                System.out.print((String) reader.readObject());
                ShellFactory.createSubshell(username, shell, "Secure Banking Dashboard", new Dashboard(reader, writer)).commandLoop();
                writer.writeObject(Message.logOutMsgOf());
                writer.flush();
            }
            return (String) reader.readObject();
        }

        @Command
        public String login( String username, String password) throws IOException, ClassNotFoundException {
            writer.writeObject(Message.loginMsgOf(username, password));
            writer.flush();
            if (reader.readBoolean())
            {
                System.out.print((String) reader.readObject());
                ShellFactory.createSubshell(username, shell, "Secure Banking Dashboard", new Dashboard(reader, writer)).commandLoop();
                writer.writeObject(Message.logOutMsgOf());
                writer.flush();
            }
            return (String) reader.readObject();
        }

        @Override
        public void cliSetShell(Shell shell) {
            this.shell = shell;
        }

    }
}

//
//    public static final InputConverter[] CLI_INPUT_CONVERTERS = {
//
//            // You can use Input Converters to support named constants
//            new InputConverter() {
//                public Integer convertInput(String original, Class<?> toClass) throws Exception {
//                    if (toClass.equals(Integer.class)) {
//                        if (original.equals("one")) return 1;
//                        if (original.equals("two")) return 2;
//                        if (original.equals("three")) return 3;
//                    }
//                    return null;
//                }
//            }
//
//    };
//
//    public static final OutputConverter[] CLI_OUTPUT_CONVERTERS = {
//
//            new OutputConverter() {
//                public Object convertOutput(Object o) {
//                    if (o.getClass().equals(Integer.class)) {
//                        int num = (Integer) o;
//
//                        if (num == 1) return "one";
//                        if (num == 2) return "two";
//                        if (num == 3) return "three";
//                    }
//                    return null;
//                }
//            }
//
//    };


