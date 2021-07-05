package dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.net.Socket;
import java.util.Date;

@Entity @NoArgsConstructor @Setter @Getter
public class Session {
    @Id @GeneratedValue
    private long sessionID;

    private String username;
    private int port;
    private String ip;
    @Temporal(TemporalType.TIMESTAMP)
    private Date startDate;
    @Temporal(TemporalType.TIMESTAMP)
    private Date endDate;

    public Session(String username, Socket socket) {
        this.username = username;
        port = socket.getPort();
        ip = socket.getInetAddress().getHostAddress();
        startDate = new Date();
    }
}
