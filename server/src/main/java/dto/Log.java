package dto;

import javax.persistence.*;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
public class Log {
    public int port;
    public String ip;
    public Date date;
    public CommandType type;
    @OneToOne
    @JoinColumn(name = "msg_ID")
    public Message msg;
    public boolean gotProcessed;

//    for when things go right:
    @OneToOne
    @JoinColumn(name = "created_user_username")
    public User createdUser;

    @OneToOne
    @JoinColumn(name = "created_session_session_id")
    public Session createdSession;
    @OneToOne
    @JoinColumn(name = "finished_session_session_id")
    public Session finishedSession;

    @ManyToOne
    @JoinColumn(name = "active_session_session_id")
    public Session activeSession;

    @OneToOne
    @JoinColumn(name = "accepted_request_acc_num")
    public PartnershipQueue acceptedRequest;

    @OneToOne
    @JoinColumn(name = "created_request_acc_num")
    public PartnershipQueue createdRequest;

    @OneToOne
    @JoinColumn(name = "created_user_account_acc_num")
    public UserAccounts createdUserAccount;

    @OneToOne
    @JoinColumn(name = "created_account_acc_num")
    public Account createdAccount;



    @OneToOne
    @JoinColumn(name = "created_transfer_ID")
    public Transfer createdTransfer;

    public List<Long> showedAccounts;

    public long showedAccountAmount;

    public long srcOriginalAmount;
    public long srcUpdatedAmount;

    public long destOriginalAmount;
    public long destUpdatedAmount;

    public IntLevel accountIntLevel;
    public IntLevel userAccountIntLevel;

    public ConfLevel accountConfLevel;
    public ConfLevel userAccountConfLevel;




//    and when they don't:
    public FailReason failReason;
//    public boolean badInput;
//    public boolean dupUsername;
//    public boolean weakPass;
//    public boolean nonExistentUsername;
//    public boolean wrongPass;
//    public boolean banUser;
//    public boolean invalidAccountNum;
//    public boolean duplicateJoinRequest;
//    public boolean invalidIntLelel;
//    public boolean invalidConfLevel;
//    public boolean invalidAccType;
//    public boolean notOwner;
//    public boolean nonExistentRequest;
//    public boolean negativeAmount;
//    public boolean noReadRight;
//    public boolean noWriteRight;
//    public boolean insufficientFunds;

    public Log(Message msg, FailReason failReason) {
        this.msg = msg;
        this.failReason = failReason;
        gotProcessed = failReason == null;
        this.date = new Date();
        this.type = msg.type;
    }
    private static final Map<String, Integer> loginCount = new HashMap<>();

    @PrePersist public void analyze()
    {
        if (type == CommandType.LOGIN)
        {
            if (gotProcessed)
                loginCount.put(msg.username, 0);
            else
                loginCount.put(msg.username, 1 + loginCount.getOrDefault(msg.username,0));
            if (loginCount.get(msg.username) > 5)
                System.err.println("ANALYZER: this is the " + loginCount.get(msg.username) + " failed attempt of " +msg.username +" to login!");
        }
        if (type == CommandType.TRANSFER )
        {
            if (accountConfLevel.level < userAccountConfLevel.level || accountIntLevel.level > userAccountIntLevel.level)
                if (gotProcessed)
                    System.err.print("!!!EXCEPTION!!! ");
            System.err.print("ANALYZER: TRANSFER: acc conf: " +accountConfLevel + " user conf: " + userAccountConfLevel +
                    " acc int: " + accountIntLevel + " user int: " + userAccountIntLevel + " got processed: " + gotProcessed);
            if (failReason != null)
                System.err.print(" because: " + failReason);
            if (accountConfLevel.level >= userAccountConfLevel.level && accountIntLevel.level <= userAccountConfLevel.level)
                System.err.println(" ANALYZER: write access");
            else
                System.err.println(" ANALYZER: no write access");
        }
        if (type == CommandType.WITHDRAW)
        {
            if (accountConfLevel.level < userAccountConfLevel.level || accountIntLevel.level > userAccountIntLevel.level)
                if (gotProcessed)
                    System.err.print("!!!EXCEPTION!!! ");
            System.err.print("ANALYZER: WITHDRAW: acc conf: " +accountConfLevel + " user conf: " + userAccountConfLevel +
                    " acc int: " + accountIntLevel + " user int: " + userAccountIntLevel + " got processed: " + gotProcessed);
            if (failReason != null)
                System.err.print(" because: " + failReason);
            if (accountConfLevel.level >= userAccountConfLevel.level && accountIntLevel.level <= userAccountIntLevel.level)
                System.err.println(" ANALYZER: write access");
            else
                System.err.println(" ANALYZER: no write access");
        }
        if (type == CommandType.SHOW_ACCOUNT && !msg.isShowAll())
        {
            if (accountConfLevel.level > userAccountConfLevel.level || accountIntLevel.level < userAccountIntLevel.level)
                if (gotProcessed)
                    System.err.print("!!!EXCEPTION!!! ");
            System.err.print("ANALYZER: SHOW_ACCOUNT: acc conf: " +accountConfLevel + " user conf: " + userAccountConfLevel +
                    " acc int: " + accountIntLevel + " user int: " + userAccountIntLevel + " got processed: " + gotProcessed);
            if (failReason != null)
                System.err.print(" because: " + failReason);
            if (accountConfLevel.level <= userAccountConfLevel.level && accountIntLevel.level >= userAccountIntLevel.level)
                System.err.println(" ANALYZER: read access");
            else
                System.err.println(" ANALYZER: no read access");
        }
    }
}
