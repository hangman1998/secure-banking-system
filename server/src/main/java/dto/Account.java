package dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;

@Entity
@Getter @Setter @NoArgsConstructor
public class Account {
    @Id
    private long accNum;
    private AccountType type;
    private IntLevel integrity;
    private ConfLevel confidentiality;
    private long amount;
    @Temporal(TemporalType.TIMESTAMP)  private Date creationDate;

    public Account(AccountType type, IntLevel integrity, ConfLevel confidentiality, long amount, long accNum) {
        this.type = type;
        this.integrity = integrity;
        this.confidentiality = confidentiality;
        this.amount = amount;
        creationDate = new Date();
        this.accNum = accNum;
    }

    @Override
    public String toString() {
        return "Account info :\n----\n" +
                "account number=" + accNum +
                ", type=" + type.toString() +
                ", integrity=" + integrity.toString() +
                ", confidentiality=" + confidentiality.toString() +
                ", creation date=" + creationDate.toString() +
                ", amount=" + amount +
                "\n-----\n";
}
}