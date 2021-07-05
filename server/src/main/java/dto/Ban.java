package dto;

import lombok.AllArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Entity
public class Ban {
    public String username;
    @Temporal(TemporalType.TIMESTAMP)
    public Date date;

    public Ban(String username) {
        this.username = username;
        date = new Date();
    }
}
