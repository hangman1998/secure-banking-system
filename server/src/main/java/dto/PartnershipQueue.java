package dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class PartnershipQueue {
    @Id
    private long accNum;
    @Id
    private String username;

    private Date requestDate = new Date();

    private boolean gotProcessed = false;

    public PartnershipQueue(long accNum, String username) {
        this.accNum = accNum;
        this.username = username;
    }
    public PartnershipQueue clone() throws CloneNotSupportedException {
        return (PartnershipQueue) super.clone();
    }
}