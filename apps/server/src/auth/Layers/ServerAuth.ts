import type {
  AuthBearerBootstrapResult,
  AuthBootstrapResult,
  AuthClientSession,
  AuthPairingCredentialResult,
  AuthSessionState,
  AuthWebSocketTokenResult,
} from "@t3tools/contracts";
import { AuthSessionId } from "@t3tools/contracts";
import { DateTime, Effect, Layer } from "effect";

import { ServerConfig } from "../../config";
import { AuthControlPlane } from "../Services/AuthControlPlane";
import {
  BootstrapCredentialError,
  BootstrapCredentialService,
} from "../Services/BootstrapCredentialService";
import { ServerAuthPolicy } from "../Services/ServerAuthPolicy";
import {
  AuthError,
  ServerAuth,
  type AuthRequest,
  type AuthenticatedSession,
  type ServerAuthShape,
} from "../Services/ServerAuth";
import {
  SessionCredentialError,
  SessionCredentialService,
} from "../Services/SessionCredentialService";

type BootstrapExchangeResult = {
  readonly response: AuthBootstrapResult;
  readonly sessionToken: string;
};

const AUTHORIZATION_PREFIX = "Bearer ";
const WEBSOCKET_TOKEN_QUERY_PARAM = "wsToken";
const LEGACY_DESKTOP_OWNER_SESSION_ID = AuthSessionId.makeUnsafe("legacy-desktop-owner");

function readLegacyDesktopToken(request: AuthRequest): string | null {
  const fromQuery = request.url?.searchParams.get("token")?.trim();
  if (fromQuery) return fromQuery;
  const fromHeader = request.headers["x-synara-legacy-token"]?.trim();
  return fromHeader && fromHeader.length > 0 ? fromHeader : null;
}

export function toBootstrapExchangeAuthError(cause: BootstrapCredentialError): AuthError {
  if (cause.status === 500) {
    return new AuthError({
      message: "Failed to validate bootstrap credential.",
      status: 500,
      cause,
    });
  }

  return new AuthError({
    message: "Invalid bootstrap credential.",
    status: 401,
    cause,
  });
}

function parseBearerToken(headers: Record<string, string | undefined>): string | null {
  const header = headers.authorization;
  if (typeof header !== "string" || !header.startsWith(AUTHORIZATION_PREFIX)) {
    return null;
  }
  const token = header.slice(AUTHORIZATION_PREFIX.length).trim();
  return token.length > 0 ? token : null;
}

function toAuthenticatedSession(session: {
  readonly sessionId: AuthenticatedSession["sessionId"];
  readonly subject: string;
  readonly method: AuthenticatedSession["method"];
  readonly role: AuthenticatedSession["role"];
  readonly expiresAt?: DateTime.DateTime;
}): AuthenticatedSession {
  return {
    sessionId: session.sessionId,
    subject: session.subject,
    method: session.method,
    role: session.role,
    ...(session.expiresAt ? { expiresAt: session.expiresAt } : {}),
  };
}

export const makeServerAuth = Effect.gen(function* () {
  const policy = yield* ServerAuthPolicy;
  const bootstrapCredentials = yield* BootstrapCredentialService;
  const authControlPlane = yield* AuthControlPlane;
  const sessions = yield* SessionCredentialService;
  const serverConfig = yield* ServerConfig;
  const descriptor = yield* policy.getDescriptor();

  const authenticateToken = (token: string): Effect.Effect<AuthenticatedSession, AuthError> =>
    sessions.verify(token).pipe(
      Effect.tapError((cause: SessionCredentialError) =>
        Effect.logWarning("Rejected authenticated session credential.").pipe(
          Effect.annotateLogs({ reason: cause.message }),
        ),
      ),
      Effect.map(toAuthenticatedSession),
      Effect.mapError(
        (cause) =>
          new AuthError({
            message: "Unauthorized request.",
            status: 401,
            cause,
          }),
      ),
    );

  const authenticateRequest: ServerAuthShape["authenticateHttpRequest"] = (request) => {
    const cookieToken = request.cookies[sessions.cookieName];
    const bearerToken = parseBearerToken(request.headers);
    const credential = cookieToken ?? bearerToken;
    if (!credential) {
      return Effect.fail(
        new AuthError({
          message: "Authentication required.",
          status: 401,
        }),
      );
    }
    return authenticateToken(credential);
  };

  const authenticateLegacyDesktopOwner = (
    request: AuthRequest,
  ): Effect.Effect<AuthenticatedSession, AuthError> => {
    if (serverConfig.mode !== "desktop" || !serverConfig.authToken) {
      return Effect.fail(
        new AuthError({
          message: "Authentication required.",
          status: 401,
        }),
      );
    }

    const legacyToken = readLegacyDesktopToken(request);
    if (!legacyToken || legacyToken !== serverConfig.authToken) {
      return Effect.fail(
        new AuthError({
          message: "Unauthorized request.",
          status: 401,
        }),
      );
    }

    return Effect.succeed({
      sessionId: LEGACY_DESKTOP_OWNER_SESSION_ID,
      subject: "desktop-bootstrap",
      method: "browser-session-cookie",
      role: "owner",
    } satisfies AuthenticatedSession);
  };

  const authenticateOwnerHttpRequest: ServerAuthShape["authenticateOwnerHttpRequest"] = (
    request,
  ) =>
    authenticateRequest(request).pipe(
      Effect.flatMap((session) =>
        session.role === "owner"
          ? Effect.succeed(session)
          : Effect.fail(
              new AuthError({
                message: "Only owner sessions can manage network access.",
                status: 403,
              }),
            ),
      ),
      Effect.catchTag("AuthError", (error) =>
        error.status === 401 ? authenticateLegacyDesktopOwner(request) : Effect.fail(error),
      ),
    );

  const getSessionState: ServerAuthShape["getSessionState"] = (request) =>
    authenticateRequest(request).pipe(
      Effect.map(
        (session) =>
          ({
            authenticated: true,
            auth: descriptor,
            requiresAuthentication: Boolean(serverConfig.authToken),
            role: session.role,
            sessionMethod: session.method,
            ...(session.expiresAt ? { expiresAt: DateTime.toUtc(session.expiresAt) } : {}),
          }) satisfies AuthSessionState,
      ),
      Effect.catchTag("AuthError", () =>
        Effect.succeed({
          authenticated: false,
          auth: descriptor,
          requiresAuthentication: Boolean(serverConfig.authToken),
        } satisfies AuthSessionState),
      ),
    );

  const exchangeBootstrapCredential: ServerAuthShape["exchangeBootstrapCredential"] = (
    credential,
    requestMetadata,
  ) =>
    bootstrapCredentials.consume(credential).pipe(
      Effect.mapError(toBootstrapExchangeAuthError),
      Effect.flatMap((grant) =>
        sessions
          .issue({
            method: "browser-session-cookie",
            subject: grant.subject,
            role: grant.role,
            client: {
              ...requestMetadata,
              ...(grant.label ? { label: grant.label } : {}),
            },
          })
          .pipe(
            Effect.mapError(
              (cause) =>
                new AuthError({
                  message: "Failed to issue authenticated session.",
                  status: 500,
                  cause,
                }),
            ),
          ),
      ),
      Effect.map(
        (session) =>
          ({
            response: {
              authenticated: true,
              role: session.role,
              sessionMethod: session.method,
              expiresAt: DateTime.toUtc(session.expiresAt),
            } satisfies AuthBootstrapResult,
            sessionToken: session.token,
          }) satisfies BootstrapExchangeResult,
      ),
    );

  const exchangeBootstrapCredentialForBearerSession: ServerAuthShape["exchangeBootstrapCredentialForBearerSession"] =
    (credential, requestMetadata) =>
      bootstrapCredentials.consume(credential).pipe(
        Effect.mapError(toBootstrapExchangeAuthError),
        Effect.flatMap((grant) =>
          sessions
            .issue({
              method: "bearer-session-token",
              subject: grant.subject,
              role: grant.role,
              client: {
                ...requestMetadata,
                ...(grant.label ? { label: grant.label } : {}),
              },
            })
            .pipe(
              Effect.mapError(
                (cause) =>
                  new AuthError({
                    message: "Failed to issue authenticated session.",
                    status: 500,
                    cause,
                  }),
              ),
            ),
        ),
        Effect.map(
          (session) =>
            ({
              authenticated: true,
              role: session.role,
              sessionMethod: "bearer-session-token",
              expiresAt: DateTime.toUtc(session.expiresAt),
              sessionToken: session.token,
            }) satisfies AuthBearerBootstrapResult,
        ),
      );

  const issuePairingCredential: ServerAuthShape["issuePairingCredential"] = (input) =>
    authControlPlane
      .createPairingLink({
        role: input?.role ?? "client",
        subject: input?.role === "owner" ? "owner-bootstrap" : "one-time-token",
        ...(input?.label ? { label: input.label } : {}),
      })
      .pipe(
        Effect.mapError(
          (cause) =>
            new AuthError({
              message: "Failed to issue pairing credential.",
              status: 500,
              cause,
            }),
        ),
        Effect.map(
          (issued) =>
            ({
              id: issued.id,
              credential: issued.credential,
              ...(issued.label ? { label: issued.label } : {}),
              expiresAt: DateTime.toUtc(issued.expiresAt),
            }) satisfies AuthPairingCredentialResult,
        ),
      );

  const listPairingLinks: ServerAuthShape["listPairingLinks"] = () =>
    authControlPlane
      .listPairingLinks({
        role: "client",
        excludeSubjects: ["owner-bootstrap"],
      })
      .pipe(
        Effect.mapError(
          (cause) =>
            new AuthError({
              message: "Failed to load pairing links.",
              status: 500,
              cause,
            }),
        ),
      );

  const revokePairingLink: ServerAuthShape["revokePairingLink"] = (id) =>
    authControlPlane.revokePairingLink(id).pipe(
      Effect.mapError(
        (cause) =>
          new AuthError({
            message: "Failed to revoke pairing link.",
            status: 500,
            cause,
          }),
      ),
    );

  const listClientSessions: ServerAuthShape["listClientSessions"] = (currentSessionId) =>
    authControlPlane.listSessions().pipe(
      Effect.mapError(
        (cause) =>
          new AuthError({
            message: "Failed to load paired clients.",
            status: 500,
            cause,
          }),
      ),
      Effect.map((clientSessions) =>
        clientSessions.map(
          (clientSession): AuthClientSession => ({
            ...clientSession,
            current: clientSession.sessionId === currentSessionId,
          }),
        ),
      ),
    );

  const revokeClientSession: ServerAuthShape["revokeClientSession"] = (
    currentSessionId,
    targetSessionId,
  ) =>
    Effect.gen(function* () {
      if (currentSessionId === targetSessionId) {
        return yield* new AuthError({
          message: "Use revoke other clients to keep the current owner session active.",
          status: 403,
        });
      }
      return yield* authControlPlane.revokeSession(targetSessionId).pipe(
        Effect.mapError(
          (cause) =>
            new AuthError({
              message: "Failed to revoke client session.",
              status: 500,
              cause,
            }),
        ),
      );
    });

  const revokeOtherClientSessions: ServerAuthShape["revokeOtherClientSessions"] = (
    currentSessionId,
  ) =>
    authControlPlane.revokeOtherSessionsExcept(currentSessionId).pipe(
      Effect.mapError(
        (cause) =>
          new AuthError({
            message: "Failed to revoke other client sessions.",
            status: 500,
            cause,
          }),
      ),
    );

  const issueWebSocketToken: ServerAuthShape["issueWebSocketToken"] = (session) =>
    sessions.issueWebSocketToken(session.sessionId).pipe(
      Effect.mapError(
        (cause) =>
          new AuthError({
            message: "Failed to issue websocket token.",
            status: 500,
            cause,
          }),
      ),
      Effect.map(
        (issued) =>
          ({
            token: issued.token,
            expiresAt: DateTime.toUtc(issued.expiresAt),
          }) satisfies AuthWebSocketTokenResult,
      ),
    );

  const authenticateWebSocketUpgrade: ServerAuthShape["authenticateWebSocketUpgrade"] = (
    request,
  ) => {
    const websocketToken = request.url?.searchParams.get(WEBSOCKET_TOKEN_QUERY_PARAM);
    if (websocketToken && websocketToken.trim().length > 0) {
      return sessions.verifyWebSocketToken(websocketToken).pipe(
        Effect.map(toAuthenticatedSession),
        Effect.mapError(
          (cause) =>
            new AuthError({
              message: "Unauthorized request.",
              status: 401,
              cause,
            }),
        ),
      );
    }

    return authenticateRequest(request);
  };

  const issueStartupPairingUrl: ServerAuthShape["issueStartupPairingUrl"] = (baseUrl) =>
    issuePairingCredential({ role: "owner" }).pipe(
      Effect.map((issued) => {
        const url = new URL(baseUrl);
        url.pathname = "/pair";
        url.searchParams.delete("token");
        url.hash = new URLSearchParams([["token", issued.credential]]).toString();
        return url.toString();
      }),
    );

  return {
    getDescriptor: () => Effect.succeed(descriptor),
    getSessionState,
    exchangeBootstrapCredential,
    exchangeBootstrapCredentialForBearerSession,
    issuePairingCredential,
    listPairingLinks,
    revokePairingLink,
    listClientSessions,
    revokeClientSession,
    revokeOtherClientSessions,
    authenticateHttpRequest: authenticateRequest,
    authenticateOwnerHttpRequest,
    authenticateWebSocketUpgrade,
    issueWebSocketToken,
    issueStartupPairingUrl,
  } satisfies ServerAuthShape;
});

export const ServerAuthLive = Layer.effect(ServerAuth, makeServerAuth);
