package com.fikua.dss.admin;

import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.web.InvalidRequestException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Objects;

/** The administration API. {@link AdminFilter} has already let the administrator in. */
@RestController
@ConditionalOnProperty("dss.admin.port")
@RequestMapping("/admin/v1")
public class AdminController {

    private static final String ADMIN = AdminFilter.ADMINISTRATOR;

    private final Administration administration;

    public AdminController(Administration administration) {
        this.administration = administration;
    }

    /** No operation without an administrator, even if the filter were not there. */
    @ModelAttribute
    void requireAdministrator(@RequestAttribute(ADMIN) Administrator by) {
        Objects.requireNonNull(by);
    }

    @GetMapping("/me")
    public Administrator me(@RequestAttribute(ADMIN) Administrator by) {
        return by;
    }

    @GetMapping("/users")
    public List<Views.User> users() {
        return administration.users();
    }

    @GetMapping("/users/{clientId}")
    public Views.User user(@PathVariable String clientId) {
        return administration.user(clientId);
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.CreatedUser create(@RequestBody Views.NewUser user, @RequestAttribute(ADMIN) Administrator by) {
        return administration.create(user, by);
    }

    @PutMapping("/users/{clientId}")
    public Views.User adopt(@PathVariable String clientId, @RequestBody Views.NewUser user,
                            @RequestAttribute(ADMIN) Administrator by) {
        return administration.adopt(new Views.NewUser(clientId, user.customer(), user.environment(),
                user.description()), by);
    }

    @PatchMapping("/users/{clientId}")
    public Views.User setActive(@PathVariable String clientId, @RequestBody Views.Active change,
                                @RequestAttribute(ADMIN) Administrator by) {
        if (change.active() == null) {
            throw new InvalidRequestException("Missing active");
        }
        return administration.setActive(clientId, change.active(), by);
    }

    @PostMapping("/users/{clientId}/secret")
    public Views.ClientSecret rotateSecret(@PathVariable String clientId, @RequestAttribute(ADMIN) Administrator by) {
        return administration.rotateSecret(clientId, by);
    }

    @GetMapping("/credentials")
    public List<Views.Credential> credentials() {
        return administration.credentials();
    }

    @PostMapping("/users/{clientId}/credentials")
    @ResponseStatus(HttpStatus.CREATED)
    public Views.CredentialPassword createCredential(@PathVariable String clientId,
                                                     @RequestAttribute(ADMIN) Administrator by) {
        return administration.createCredential(clientId, by);
    }

    @GetMapping(value = "/credentials/{id}/csr", produces = "application/pkcs10")
    public String csr(@PathVariable String id, @RequestParam(required = false) String subject,
                      @RequestAttribute(ADMIN) Administrator by) {
        return administration.csr(id, subject, by);
    }

    @PutMapping(value = "/credentials/{id}/certificate",
            consumes = {"application/x-pem-file", MediaType.TEXT_PLAIN_VALUE})
    public Views.Credential installCertificate(@PathVariable String id, @RequestBody String pem,
                                               @RequestAttribute(ADMIN) Administrator by) {
        return administration.installCertificate(id, pem, by);
    }

    @PostMapping("/credentials/{id}/password")
    public Views.CredentialPassword rotatePassword(@PathVariable String id,
                                                   @RequestBody(required = false) Views.Rotation rotation,
                                                   @RequestAttribute(ADMIN) Administrator by) {
        return administration.rotatePassword(id, rotation == null ? null : rotation.overlapHours(), by);
    }

    @DeleteMapping("/credentials/{id}")
    public Views.Credential revoke(@PathVariable String id, @RequestAttribute(ADMIN) Administrator by) {
        return administration.revoke(id, by);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> notFound(NotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("not_found", e.getMessage()));
    }

    @ExceptionHandler(ClientsUnavailableException.class)
    public ResponseEntity<ErrorResponse> unavailable(ClientsUnavailableException e) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(new ErrorResponse("authorization_server_unavailable", e.getMessage()));
    }

    /** Two requests for the same id at the same time. */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> conflict() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("conflict", "There is something with that id"));
    }
}
