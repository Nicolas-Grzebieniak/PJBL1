package com.pucpr.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    public void handleLogin(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            Map<?, ?> body = mapper.readValue(exchange.getRequestBody(), Map.class);
            String email = (String) body.get("email");
            String senha = (String) body.get("senha");

            Optional<Usuario> usuarioOpt = repository.findByEmail(email);


            if (usuarioOpt.isEmpty() || !BCrypt.checkpw(senha, usuarioOpt.get().getSenhaHash())) {
                sendResponse(exchange, 401, "{\"erro\": \"E-mail ou senha inválidos.\"}");
                return;
            }

            String token = jwtService.generateToken(usuarioOpt.get());
            sendResponse(exchange, 200, "{\"token\": \"" + token + "\"}");

        } catch (Exception e) {
            System.err.println("Erro no login: " + e.getMessage());
            sendResponse(exchange, 500, "{\"erro\": \"Erro interno.\"}");
        }
    }

    public void handleRegister(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            Map<?, ?> body = mapper.readValue(exchange.getRequestBody(), Map.class);
            String nome  = (String) body.get("nome");
            String email = (String) body.get("email");
            String senha = (String) body.get("senha");
            String role  = (String) body.get("role");

            if (repository.findByEmail(email).isPresent()) {
                sendResponse(exchange, 400, "{\"erro\": \"E-mail já cadastrado.\"}");
                return;
            }


            String senhaHash = BCrypt.hashpw(senha, BCrypt.gensalt(12));

            Usuario novoUsuario = new Usuario(nome, email, senhaHash, role);
            repository.save(novoUsuario);

            sendResponse(exchange, 201, "{\"mensagem\": \"Usuário cadastrado com sucesso.\"}");

        } catch (Exception e) {
            System.err.println("Erro no cadastro: " + e.getMessage());
            sendResponse(exchange, 500, "{\"erro\": \"Erro interno.\"}");
        }
    }

    public void handleProtected(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendResponse(exchange, 401, "{\"erro\": \"Token ausente.\"}");
            return;
        }

        String token = authHeader.substring(7);

        if (!jwtService.validateToken(token)) {
            sendResponse(exchange, 401, "{\"erro\": \"Token inválido ou expirado.\"}");
            return;
        }

        String email = jwtService.extractEmail(token);
        sendResponse(exchange, 200, "{\"mensagem\": \"Acesso autorizado.\", \"usuario\": \"" + email + "\"}");
    }



    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
    }

    private void sendResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}