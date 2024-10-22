package com.aa_authservice.authservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.List;

import com.aa_authservice.authservice.dto.EncryptedRequest;
import com.aa_authservice.authservice.modal.User;
import com.aa_authservice.authservice.repository.UserRepository;
import com.aa_authservice.authservice.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Value("${SECRET_KEY}")
    private String SECRET_KEY;

    @Autowired
    private UserService userService;

    final String ALGORITHM = "AES";
    final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    final int IV_SIZE = 16;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody EncryptedRequest encryptedRequest, HttpServletResponse response) {
        try {
            // Decrypting the request body
            System.out.println("Encrypted data received: " + encryptedRequest.getData());
            String decryptedData = decryptData(encryptedRequest.getData());
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> requestData = objectMapper.readValue(decryptedData, Map.class);
            String email = requestData.get("email");
            String password = requestData.get("password");

            // Make HTTP request to Keycloak for access token
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", "aa-nishkaiv");
            body.add("client_secret", "m8odr85yda6mcV6NASNn25Oqu7WHeLIv");
            body.add("grant_type", "password");
            body.add("username", email);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            ResponseEntity<Map> keycloakResponse = restTemplate.postForEntity(
                    "http://api.kriate.co.in:8346/realms/master/protocol/openid-connect/token", entity, Map.class);

            if (keycloakResponse.getStatusCode() != HttpStatus.OK) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid login credentials");
            }

            Map<String, Object> tokenResponse = keycloakResponse.getBody();
            String refreshToken = (String) tokenResponse.get("refresh_token");
            String accessToken = (String) tokenResponse.get("access_token");

            // Decode JWT and extract 'sid'
            String[] jwtParts = refreshToken.split("\\.");
            String payloadJson = new String(Base64.getDecoder().decode(jwtParts[1]));
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload = mapper.readTree(payloadJson);
            String sessionId = payload.get("sid").asText();

            // Fetch user from the database
            Optional<User> userOpt = userRepository.findByUserEmail(email);
            if (!userOpt.isPresent()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }

            User user = userOpt.get();
            user.setSessionId(sessionId);
            userRepository.save(user);

            // Set the refresh token as an HTTP cookie
            ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

            // Create and return the response
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("userId", user.getId());
            responseBody.put("userName", user.getUserName());
            responseBody.put("userEmail", user.getUserEmail());
            responseBody.put("sessionId", sessionId);
            responseBody.put("accessToken", accessToken);

            return ResponseEntity.ok(responseBody);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    public String decryptData(String data) {
        try {
            System.out.println("data:-" + data);
            byte[] encryptedDataWithIv = Base64.getDecoder().decode(data);

            byte[] iv = new byte[IV_SIZE];
            byte[] encryptedData = new byte[encryptedDataWithIv.length - IV_SIZE];
            System.arraycopy(encryptedDataWithIv, 0, iv, 0, IV_SIZE);
            System.arraycopy(encryptedDataWithIv, IV_SIZE, encryptedData, 0, encryptedData.length);

            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes("UTF-8"), ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] decryptedBytes = cipher.doFinal(encryptedData);

            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            String errorMessage = "Decryption error: " + e.getMessage();
            System.err.println(errorMessage);
            return null;
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get the refreshToken from cookies
            String refreshToken = null;
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if (cookie.getName().equals("refreshToken")) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No refresh token found in cookies");
            }
            System.out.println("Refresh Token: " + refreshToken);

            // Prepare the Keycloak logout request
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", "aa-nishkaiv");
            body.add("client_secret", "m8odr85yda6mcV6NASNn25Oqu7WHeLIv");
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            // Send the logout request to Keycloak
            ResponseEntity<String> keycloakResponse = restTemplate.exchange(
                    "http://api.kriate.co.in:8346/realms/master/protocol/openid-connect/logout",
                    HttpMethod.POST,
                    entity,
                    String.class);

            System.out.println("Keycloak Response Status: " + keycloakResponse.getStatusCode());
            System.out.println("Keycloak Response Body: " + keycloakResponse.getBody());
            
            if (keycloakResponse.getStatusCode() != HttpStatus.NO_CONTENT) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to logout from Keycloak");
            }

            // Clear the refreshToken cookie
            ResponseCookie clearRefreshToken = ResponseCookie.from("refreshToken", null)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader("Set-Cookie", clearRefreshToken.toString());

            return ResponseEntity.ok("User logged out");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @GetMapping("/check-session")
    public ResponseEntity<Object> checkSession(HttpServletRequest request) {
        try {
            String refreshToken = null;

            // Retrieve the refresh token from cookies
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("refreshToken".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            // Check if refresh token is present
            if (refreshToken == null) {
                return ResponseEntity.ok().body("missing token");
            }

            // Decode the JWT manually
            String[] jwtParts = refreshToken.split("\\.");
            if (jwtParts.length < 2) {
                return ResponseEntity.status(400).body("Invalid refresh token format");
            }

            String base64EncodedBody = jwtParts[1];
            String body;

            try {
                body = new String(Base64.getDecoder().decode(base64EncodedBody));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body("Failed to decode token");
            }

            // Parse the JWT body to extract information
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload;
            try {
                payload = mapper.readTree(body);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Failed to parse token payload");
            }

            // Extracting "sid" and "sub" from the token payload
            String sid = payload.get("sid").asText();
            String sub = payload.get("sub").asText();

            System.out.println("sid"+sid+":sub:"+sub);
            // Check user existence in the database
            boolean userExists = userService.checkUserExistsBySidAndSub(sid, sub);
            if (!userExists) {
                return ResponseEntity.ok().body("invalid");
            }

            return ResponseEntity.ok().body("valid");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @GetMapping("/logged-in-user")
    public ResponseEntity<Object> getLoggedInUser(HttpServletRequest request) {
        try {
            String refreshToken = null;

            // Retrieve the refresh token from cookies
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if (cookie.getName().equals("refreshToken")) { // Adjust cookie name if needed
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            if (refreshToken == null) {
                return ResponseEntity.status(404).body("No refresh token");
            }

            // Decode the refresh token (without claims)
            String[] jwtParts = refreshToken.split("\\.");
            if (jwtParts.length < 2) {
                return ResponseEntity.status(400).body("Invalid refresh token format");
            }

            String base64EncodedBody = jwtParts[1];
            String body;
            try {
                body = new String(Base64.getDecoder().decode(base64EncodedBody));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body("Failed to decode token");
            }

            // Assuming you use Jackson for JSON processing
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload = mapper.readTree(body);
            String sub = payload.get("sub").asText();

            // Fetch user from the database
            Optional<User> userOptional = userService.findById(sub); // Adjust method name as needed
            if (!userOptional.isPresent()) {
                return ResponseEntity.status(404).body("No user found");
            }

            return ResponseEntity.ok(userOptional.get());

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @GetMapping("/regenerate-accesstoken")
    public ResponseEntity<String> regenerateAccessToken(HttpServletRequest request, HttpServletResponse response) {

        String refreshToken = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("refreshToken")) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        System.out.println("REFRESH tOKEN:-"+refreshToken);

        if (refreshToken == null) {
            return ResponseEntity.status(400).body("No refresh token found");
        }
        String url = "http://api.kriate.co.in:8346/realms/master/protocol/openid-connect/token";

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", "aa-nishkaiv");
        body.add("client_secret", "m8odr85yda6mcV6NASNn25Oqu7WHeLIv");
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);
        try {
            ResponseEntity<String> res = restTemplate.postForEntity(url, requestEntity, String.class);
            System.out.println(res);
            if (res.getStatusCode().is2xxSuccessful()) {
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode jsonNode = objectMapper.readTree(res.getBody());
                String accessToken = jsonNode.get("access_token").asText();
                return ResponseEntity.ok(accessToken);
            } else {

                return ResponseEntity.status(res.getStatusCode()).body("Failed to get access token from keycloak");
            }
        } catch (Exception e) {

            e.printStackTrace();
            return ResponseEntity.status(500).body("Error during getting access token:" +
                    e.getMessage());
        }
    }

}
