package dto;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import java.util.Date;
import java.util.List;

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
}
