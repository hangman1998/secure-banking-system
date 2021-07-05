package dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Entity
@Getter @Setter @NoArgsConstructor
public class User {
    @Id
    private String username;
    private byte[] passwordHash;
    private byte[] salt;
    private Date creationDate = new Date();

    public User(String username, byte[] passwordHash, byte[] salt) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.salt = salt;
    }
}