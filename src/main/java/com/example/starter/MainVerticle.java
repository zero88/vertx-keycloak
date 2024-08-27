package com.example.starter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CSRFHandler;
import io.vertx.ext.web.handler.OAuth2AuthHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;

public class MainVerticle extends AbstractVerticle {

    private JsonObject webConfig() {
        return new JsonObject().put("http.port", 9999)
                               .put("http.publicDomain", "http://localhost:9999")
                               .put("auth.csrfSecret", "zwiebelfische")
                               .put("auth.protectedPath", "/protected/*")
                               .put("auth.oauth2CallbackPath", "/callback")
                               .put("auth.oauth2ClientId", "demo-client")
                               .put("auth.oauth2ClientSecret", null)
                               .put("auth.oauth2GrantType", "authorization_code")
                               .put("auth.oauth2Scopes", null)
                               .put("auth.oauth2ExtraParams", null)
                               .put("auth.oauth2PCKEVerifierLength", -1)
                               .put("auth.oauth2Issuer", "http://localhost:8080/realms/vertx")
                               .put("auth.oauth2RedirectUri", "/login");
    }

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        JsonObject webConfig = webConfig();
        Router router = Router.router(vertx);
        SessionHandler sessionHandler = SessionHandler.create(LocalSessionStore.create(vertx));
        CSRFHandler csrfHandler = CSRFHandler.create(vertx, webConfig.getString("auth.csrfSecret"));
        router.route().handler(sessionHandler) // session handler
              .handler(BodyHandler.create())  // Expose form parameters in request
              .handler(csrfHandler); // CSRF handler setup required for logout form

        setupAuthRoutes(router, webConfig);

        int port = webConfig.getInteger("http.port");
        vertx.createHttpServer().requestHandler(router).listen(port).onComplete(http -> {
            if (http.succeeded()) {
                startPromise.complete();
                System.out.println("HTTP server started on port " + port);
            } else {
                startPromise.fail(http.cause());
            }
        });
    }

    private void setupAuthRoutes(Router router, JsonObject webConfig) {
        OAuth2Options options = new OAuth2Options().setSite(webConfig.getString("auth.oauth2Issuer"))
                                                   .setClientId(webConfig.getString("auth.oauth2ClientId"))
                                                   .setClientSecret(webConfig.getString("auth.oauth2ClientSecret"))
                                                   .setTenant("auth.oauth2Tenant");
        KeycloakAuth.discover(vertx, options).onSuccess(oAuth2Auth -> {
            String callbackPath = webConfig.getString("auth.oauth2CallbackPath");
            String callbackUrl = webConfig.getString("http.publicDomain") + callbackPath;
            List<String> scopes = Optional.ofNullable(webConfig.getJsonArray("auth.oauth2Scopes"))
                                          .map(lst -> (List<String>) lst.getList())
                                          .orElseGet(ArrayList::new);
            JsonObject extraParams = webConfig.getJsonObject("auth.oauth2ExtraParams");
            Integer pckeVerifierLength = webConfig.getInteger("auth.oauth2PCKEVerifierLength");
            String prompt = webConfig.getString("auth.oauth2Prompt");
            OAuth2AuthHandler authHandler = OAuth2AuthHandler.create(vertx, oAuth2Auth, callbackUrl)
                                                             .setupCallback(router.get(callbackPath))
                                                             .withScopes(scopes)
                                                             .extraParams(extraParams)
                                                             .pkceVerifierLength(pckeVerifierLength)
                                                             .prompt(prompt);
            router.route(webConfig.getString("auth.protectedPath")).handler(authHandler);
            configWebRoute(router, oAuth2Auth);
        }).onFailure(System.err::println);
    }

    private void configWebRoute(Router router, OAuth2Auth oAuth2Auth) {
        router.get("/").handler(this::handleIndex);
        router.get("/protected/").handler(this::handleGreet);
        router.get("/protected/user").handler(this::handleUserPage);
        router.get("/protected/admin").handler(this::handleAdminPage);
        router.get("/protected/userinfo").handler(rc -> this.handleUserInfo(rc, oAuth2Auth));
        router.post("/logout").handler(this::handleLogout);
    }

    private void handleUserInfo(RoutingContext ctx, OAuth2Auth oAuth2Auth) {
        User user = ctx.user();
        // extract discovered userinfo endpoint url
        OAuth2Options config = ((OAuth2AuthProviderImpl) oAuth2Auth).getConfig();
        oAuth2Auth.userInfo(user)
                  .onSuccess(userJson -> respondWithOk(ctx, "application/json",
                                                       JsonObject.of("user", userJson, "config", config.toJson())
                                                                 .toBuffer()));
    }

    private void handleLogout(RoutingContext ctx) {
        User user = ctx.user();

        if (user == null) {
            respondWithServerError(ctx, "text/html",
                                   Buffer.buffer(String.format("<h1>Request failed %s</h1>", "user missing")));
            return;
        }

        //    user.logout(res -> {
        //
        //      if (!res.succeeded()) {
        //        // the user might not have been logged out, to know why:
        //        respondWithServerError(ctx, "text/html", String.format("<h1>Logout failed %s</h1>", res.cause()));
        //        return;
        //      }
        //
        //      ctx.session().destroy();
        //      ctx.response().setStatusCode(302).putHeader("location", "/?logout=true").end();
        //    });
    }

    private void handleAdminPage(RoutingContext ctx) {
        User user = ctx.user();

        if (user == null) {
            respondWithServerError(ctx, "text/html",
                                   Buffer.buffer(String.format("<h1>Request failed %s</h1>", "user missing")));
            return;
        }

        // check for realm-role "admin"
        user.isAuthorized("realm:admin", res -> {

            if (!res.succeeded() || !res.result()) {
                respondWith(ctx, 403, "text/html", Buffer.buffer("<h1>Forbidden</h1>"));
                return;
            }

            String username = user.principal().getString("preferred_username");

            String content = String.format("<h1>Admin Page: %s @%s</h1><a href=\"/protected/\">Protected Area</a>",
                                           username, Instant.now());
            respondWithOk(ctx, "text/html", Buffer.buffer(content));
        });
    }

    private void handleUserPage(RoutingContext ctx) {
        User user = ctx.user();

        if (user == null) {
            respondWithServerError(ctx, "text/html",
                                   Buffer.buffer(String.format("<h1>Request failed %s</h1>", "user missing")));
            return;
        }

        // extract username from IDToken, there are many more claims like (email, givenanme, familyname etc.) available
        JsonObject userJson = JsonObject.of("principal", user.principal())
                                        .put("attributes", user.attributes())
                                        .put("subject", user.subject())
                                        .put("auths", user.authorizations().getProviderIds().stream().toList())
                                        .put("time", Instant.now());
        respondWithOk(ctx, "application/json", userJson.toBuffer());
    }

    private void handleGreet(RoutingContext ctx) {
        User user = ctx.user();

        if (user == null) {
            respondWithServerError(ctx, "text/html",
                                   Buffer.buffer(String.format("<h1>Logout failed %s</h1>", "user missing")));
            return;
        }

        String username = user.principal().getString("preferred_username");
        String displayName = user.principal().getString("name");

        String greeting = String.format(
            "<h1>Hi %s (%s) @%s</h1><ul>" + "<li><a href=\"/protected/user\">User Area</a></li>" +
            "<li><a href=\"/protected/admin\">Admin Area</a></li>" +
            "<li><a href=\"/protected/userinfo\">User Info (Remote Call)</a></li>" + "</ul>", username, displayName,
            Instant.now());

        String logoutForm = createLogoutForm(ctx);

        respondWithOk(ctx, "text/html", Buffer.buffer(greeting + logoutForm));
    }

    private String createLogoutForm(RoutingContext ctx) {
        String csrfToken = ctx.get(CSRFHandler.DEFAULT_HEADER_NAME);

        return "<form action=\"/logout\" method=\"post\" enctype='multipart/form-data'>" +
               String.format("<input type=\"hidden\" name=\"%s\" value=\"%s\">", CSRFHandler.DEFAULT_HEADER_NAME,
                             csrfToken) + "<button>Logout</button></form>";
    }

    private void handleIndex(RoutingContext ctx) {
        respondWithOk(ctx, "text/html", Buffer.buffer(
            "<h1>Welcome to Vert.x Keycloak Example</h1><br><a href=\"/protected/\">Protected</a>"));
    }

    private void respondWithOk(RoutingContext ctx, String contentType, Buffer content) {
        respondWith(ctx, 200, contentType, content);
    }

    private void respondWithServerError(RoutingContext ctx, String contentType, Buffer content) {
        respondWith(ctx, 500, contentType, content);
    }

    private void respondWith(RoutingContext ctx, int statusCode, String contentType, Buffer content) {
        ctx.response().setStatusCode(statusCode).putHeader("content-type", contentType).end(content);
    }

}
