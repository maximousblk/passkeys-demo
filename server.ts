import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "https://deno.land/x/simplewebauthn@v8.1.1/deno/server.ts";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "https://deno.land/x/simplewebauthn@v8.1.1/deno/typescript-types.ts";
import { jwtVerify, SignJWT } from "https://deno.land/x/jose@v4.14.6/index.ts";
import { Hono } from "https://deno.land/x/hono@v3.6.3/mod.ts";
import { getSignedCookie, logger, serveStatic, setSignedCookie } from "https://deno.land/x/hono@v3.6.3/middleware.ts";

// CONSTANTS

const SECRET = new TextEncoder().encode(Deno.env.get("JWT_SECRET") ?? "development");
const DATABASE = Deno.env.get("DENO_DEPLOYMENT_ID") ? undefined : "users.db";
const RP_ID = Deno.env.get("WEBAUTHN_RP_ID") ?? "localhost";
const RP_NAME = Deno.env.get("WEBAUTHN_RP_NAME") ?? "Deno Passkeys Demo";
const CHALLENGE_TTL = Number(Deno.env.get("WEBAUTHN_CHALLENGE_TTL")) || 60_000;

// UTILS

function generateJWT(userId: string) {
  return new SignJWT({ userId }).setProtectedHeader({ alg: "HS256" }).sign(SECRET);
}

function verifyJWT(token: string) {
  return jwtVerify(token, SECRET);
}

function generateRandomID() {
  const id = crypto.getRandomValues(new Uint8Array(32));

  return btoa(
    Array.from(id)
      .map((c) => String.fromCharCode(c))
      .join(""),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// DATABASE

const kv = await Deno.openKv(DATABASE);

type User = {
  username: string;
  data: string;
  credentials: Record<string, Credential>;
};

type Credential = {
  credentialID: Uint8Array;
  credentialPublicKey: Uint8Array;
  counter: number;
};

type Challenge = true;

// RP SERVER

const app = new Hono();

app.use("*", logger());

app.get("/", serveStatic({ path: "./index.html" }));

app.post("/register/options", async (c) => {
  const { username } = await c.req.json<{ username: string }>();
  console.log({ username });

  const userID = generateRandomID();

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID,
    userName: username,
    userDisplayName: username,
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
      authenticatorAttachment: "platform",
    },
  });

  console.log({ options });

  await kv.set(["challenges", options.challenge], true, {
    expireIn: CHALLENGE_TTL,
  });

  await setSignedCookie(c, "userId", userID, SECRET, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: CHALLENGE_TTL,
  });

  return c.json(options);
});

app.post("/register/verify", async (c) => {
  const { username, cred } = await c.req.json<{ username: string; cred: RegistrationResponseJSON }>();
  console.log({ username, cred });

  const userId = await getSignedCookie(c, SECRET, "userId");
  if (!userId) return new Response("Unauthorized", { status: 401 });
  console.log({ userId });

  const clientData = JSON.parse(atob(cred.response.clientDataJSON));
  console.log({ clientData });

  const challenge = await kv.get<Challenge>(["challenges", clientData.challenge]);
  console.log({ challenge });

  if (!challenge.value) {
    return c.text("Invalid challenge", 400);
  }

  const verification = await verifyRegistrationResponse({
    response: cred,
    expectedChallenge: clientData.challenge,
    expectedRPID: RP_ID,
    expectedOrigin: c.req.header("origin")!, //! Allow from any origin
    requireUserVerification: true,
  });
  console.log({ verification });

  if (verification.verified) {
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo!;

    await kv.delete(["challenges", clientData.challenge]);

    await kv.set(["users", userId], {
      username: username,
      data: "Private user data for " + (username || "Anon"),
      credentials: {
        [cred.id]: {
          credentialID,
          credentialPublicKey,
          counter,
        },
      },
    } as User);

    await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 600_000,
    });

    return c.json(verification);
  }

  return c.text("Unauthorized", 401);
});

app.post("/login/options", async (c) => {
  const options = await generateAuthenticationOptions({
    userVerification: "required",
    rpID: RP_ID,
  });

  console.log({ options });

  await kv.set(["challenges", options.challenge], true, {
    expireIn: CHALLENGE_TTL,
  });

  return c.json(options);
});

app.post("/login/verify", async (c) => {
  const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>();
  console.log({ cred });

  const clientData = JSON.parse(atob(cred.response.clientDataJSON));
  console.log({ clientData });

  const userId = cred.response.userHandle;
  console.log({ userId });
  if (!userId) return c.text("Unauthorized", 401);

  const user = await kv.get<User>(["users", userId]);
  if (!user.value) return c.text("Unauthorized", 401);
  console.log({ user });

  const challenge = await kv.get<Challenge>(["challenges", clientData.challenge]);
  if (!challenge.value) {
    return c.text("Invalid challenge", 400);
  }

  const verification = await verifyAuthenticationResponse({
    response: cred,
    expectedChallenge: clientData.challenge,
    expectedOrigin: c.req.header("origin")!, //! Allow from any origin
    expectedRPID: RP_ID,
    authenticator: user.value.credentials[cred.id],
  });

  if (verification.verified) {
    const { newCounter } = verification.authenticationInfo;

    await kv.delete(["challenges", clientData.challenge]);

    const newUser = user.value;
    newUser.credentials[cred.id].counter = newCounter;

    await kv.set(["users", userId], newUser);

    await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 600_000,
    });

    return c.json(verification);
  }

  return c.text("Unauthorized", 401);
});

app.get("/private", async (c) => {
  const token = await getSignedCookie(c, SECRET, "token");
  if (!token) return new Response("Unauthorized", { status: 401 });
  console.log({ token });

  const result = await verifyJWT(token);
  console.log({ result });

  const user = await kv.get<User>(["users", result.payload.userId as string]);
  if (!user.value) return new Response("Unauthorized", { status: 401 });

  return c.json({
    id: result.payload.userId,
    username: user.value.username || "Anon",
    data: user.value.data,
  });
});

Deno.serve({ port: 80 }, app.fetch);
