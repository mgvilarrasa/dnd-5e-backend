package com.mgv.dnd.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "auth_tokens")
public class Token {
    @Id
    public String id;

    @Column(unique = true)
    public String token;

    public String tokenType;

    public boolean revoked;

    public boolean expired;

    public String userId;
}
