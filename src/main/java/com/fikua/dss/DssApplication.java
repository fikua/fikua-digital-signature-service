package com.fikua.dss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DssApplication {

    public static void main(String[] args) {
        var context = SpringApplication.run(DssApplication.class, args);
        // An operator command has already run: end instead of serving.
        if (context.getEnvironment().containsProperty("dss.command")) {
            System.exit(SpringApplication.exit(context));
        }
    }
}
