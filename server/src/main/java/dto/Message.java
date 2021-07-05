package dto;

import lombok.Getter;

import javax.persistence.Entity;

@Getter @Entity
public class Message implements java.io.Serializable{
    CommandType type;

    String username;
    String password;

    IntLevel intLevel;
    ConfLevel confLevel;

    long accountNum;
    AccountType accountType;
    long initialAmount;

    long fromAccNum;
    long toAccNum;
    long amount;

    boolean showAll;

    public void destroyPassword()
    {
        if (password != null)
            password = "****";
    }

    public static Message acceptMsgOf(long accountNum, String username, IntLevel intLevel, ConfLevel confLevel )
    {
        Message msg = new Message();
        msg.type = CommandType.ACCEPT_JOIN;
        msg.accountNum = accountNum;
        msg.confLevel = confLevel;
        msg.username = username;
        msg.intLevel = intLevel;
        return msg;
    }
    public static Message createMsgOf(AccountType accountType, long initialAmount, IntLevel intLevel, ConfLevel confLevel )
    {
        Message msg = new Message();
        msg.type = CommandType.CREATE_ACCOUNT;
        msg.confLevel = confLevel;
        msg.intLevel = intLevel;
        msg.accountType = accountType;
        msg.initialAmount = initialAmount;
        return msg;
    }
    public static Message depositMsgOf(long toAccNum, long amount )
    {
        Message msg = new Message();
        msg.type = CommandType.DEPOSIT;
        msg.toAccNum = toAccNum;
        msg.amount = amount;
        return msg;
    }
    public static Message withdrawMsgOf(long fromAccNum, long amount )
    {
        Message msg = new Message();
        msg.type = CommandType.WITHDRAW;
        msg.fromAccNum = fromAccNum;
        msg.amount = amount;
        return msg;
    }

    public static Message transferMsgOf(long fromAccNum, long toAccNum, long amount )
    {
        Message msg = new Message();
        msg.type = CommandType.TRANSFER;
        msg.fromAccNum = fromAccNum;
        msg.toAccNum = toAccNum;
        msg.amount = amount;
        return msg;
    }
    public static Message joinMsgOf(long accountNum)
    {
        Message msg = new Message();
        msg.type = CommandType.REQUEST_JOIN;
        msg.accountNum = accountNum;
        return msg;
    }
    public static Message loginMsgOf(String username, String password )
    {
        Message msg = new Message();
        msg.type = CommandType.LOGIN;
        msg.username = username;
        msg.password = password;
        return msg;
    }
    public static Message signupMsgOf(String username, String password )
    {
        Message msg = new Message();
        msg.type = CommandType.SIGN_UP;
        msg.username = username;
        msg.password = password;
        return msg;
    }
    public static Message showMsgOf(long accountNum, boolean showAll)
    {
        Message msg = new Message();
        msg.type = CommandType.SHOW_ACCOUNT;
        msg.accountNum = accountNum;
        msg.showAll = showAll;
        return msg;
    }
    public static Message terminateMsgOf()
    {
        Message msg = new Message();
        msg.type = CommandType.TERMINATE;
        return msg;
    }
    public static Message logOutMsgOf()
    {
        Message msg = new Message();
        msg.type = CommandType.LOGOUT;
        return msg;
    }
}
