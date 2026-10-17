package com.example;

import java.io.File;
import java.sql.Connection;
import java.sql.Statement;
import java.net.URL;

import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @GetMapping("/search")
    public String search(@RequestParam String q) throws Exception {
        // SQL injection
        String sql = "SELECT * FROM users WHERE name = '" + q + "'";
        Statement st = connection.createStatement();
        st.executeQuery(sql);

        // Command injection
        Runtime.getRuntime().exec("echo " + q);

        // SSRF
        URL url = new URL(q);
        url.openConnection();

        // Path traversal
        File f = new File("/var/www/" + q);

        return "hello " + q;
    }

    @PostMapping("/reflect")
    public String reflect(@RequestBody String body, HttpServletResponse response) throws Exception {
        response.getWriter().write(body);
        return body;
    }
}
