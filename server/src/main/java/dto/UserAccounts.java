package dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class UserAccounts {
    @Id
    private long accNum;
    @Id
    private String username;
    private boolean isOwner;
    private IntLevel integrity;
    private ConfLevel confidentiality;
    private Date joinDate = new Date();

    public  UserAccounts(long accNum, String username, boolean isOwner, IntLevel integrity, ConfLevel confidentiality) {
        this.accNum = accNum;
        this.username = username;
        this.isOwner = isOwner;
        this.integrity = integrity;
        this.confidentiality = confidentiality;
    }
}