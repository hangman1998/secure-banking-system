package dto;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;


@Entity @AllArgsConstructor @NoArgsConstructor
public class StoredKeyPair {
//    public key and private key are encoded and then saved in base64
    @Id private String publicKey;
    private String privateKey;
}
