package com.aa_authservice.authservice.modal;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Column;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_master")
public class User {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "userName", nullable = false)
    private String userName;

    @Column(name = "userEmail", nullable = false)
    private String userEmail;

    @Column(name = "sessionId")
    private String sessionId;

    @Column(name = "roles")  // New column to store roles as a comma-separated string
    private String roles;

    public User() {
    }

    public User(String id, String userName, String userEmail, String sessionId, String roles) {
        this.id = id;
        this.userName = userName;
        this.userEmail = userEmail;
        this.sessionId = sessionId;
        this.roles = roles;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }
}
