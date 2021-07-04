package dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserAccounts {
    @Id
    private long accNum;
    @Id
    private String username;
    private boolean isOwner;
    private IntLevel integrity;
    private ConfLevel confidentiality;
}