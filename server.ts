import SimpleWebAuthnServer from 'npm:@simplewebauthn/server@7.2.0';
import { jwtVerify, SignJWT } from 'https://deno.land/x/jose@v4.14.4/index.ts';

const SECRET = new TextEncoder().encode('development');

function generateJWT(userId: string) {
  return new SignJWT({ userId }).setProtectedHeader({ alg: 'HS256' }).sign(SECRET);
}

function verifyJWT(token: string) {
  return jwtVerify(token, SECRET);
}

function generateRandomID() {
  const id = crypto.getRandomValues(new Uint8Array(32));

  return btoa(
    Array.from(id)
      .map((c) => String.fromCharCode(c))
      .join('')
  )
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// DATABASE

const kv = await Deno.openKv('./users.db');

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

type Challenge = {
  timeout: number;
};

// RP SERVER

const homepage = await Deno.readTextFile('index.html');

const handler: Deno.ServeHandler = async (req) => {
  const url = new URL(req.url);

  switch (url.pathname) {
    case '/': {
      return new Response(homepage, {
        headers: { 'content-type': 'text/html' },
      });
    }

    case '/register/options': {
      console.log(req.method, req.url);

      const json = await req.json();
      console.log({ json });

      const userID = generateRandomID();

      const options = SimpleWebAuthnServer.generateRegistrationOptions({
        rpName: 'Passkeys Demo',
        rpID: req.headers.get('host')!,
        userID,
        userName: json.username,
        userDisplayName: json.username,
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
          authenticatorAttachment: 'platform',
        },
      });

      console.log({ options });

      await kv.set(['challenges', options.challenge], { timeout: Date.now() + 60_000 } as Challenge);

      return new Response(JSON.stringify(options), {
        headers: {
          'content-type': 'application/json',
          'set-cookie': `userId=${userID}; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=${new Date(Date.now() + 60_000).toUTCString()}`,
        },
      });
    }

    case '/register/verify': {
      console.log(req.method, req.url);

      const json = await req.json();
      console.log({ json });

      const cookie = req.headers.get('cookie');
      if (!cookie) return new Response('Unauthorized', { status: 401 });
      console.log({ cookie });

      const userId = cookie
        .split(';')
        .find((c) => c.trim().startsWith('userId='))
        ?.split('=')[1];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      console.log({ userId });

      const clientData = JSON.parse(atob(json.cred.response.clientDataJSON));
      console.log({ clientData });

      const challenge = await kv.get<Challenge>(['challenges', clientData.challenge]);
      console.log({ challenge });

      if (!challenge.value || challenge.value.timeout < Date.now()) {
        return new Response('Challenge expired', { status: 400 });
      }

      const verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
        response: json.cred,
        expectedChallenge: clientData.challenge,
        expectedRPID: req.headers.get('host')!,
        expectedOrigin: req.headers.get('origin')!,
        requireUserVerification: true,
      });
      console.log({ verification });

      if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } = verification.registrationInfo!;

        await kv.delete(['challenges', clientData.challenge]);

        await kv.set(['users', userId], {
          username: json.username,
          data: "Demo user's data",
          credentials: {
            [json.cred.id]: {
              credentialID,
              credentialPublicKey,
              counter,
            },
          },
        } as User);

        return new Response(JSON.stringify(verification), {
          headers: {
            'content-type': 'application/json',
            'set-cookie': `token=${await generateJWT(userId)}; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=${new Date(Date.now() + 600_000).toUTCString()}`,
          },
        });
      }

      return new Response('Unauthorized', { status: 401 });
    }

    case '/login/options': {
      console.log(req.method, req.url);

      const options = SimpleWebAuthnServer.generateAuthenticationOptions({
        userVerification: 'required',
        rpID: req.headers.get('host')!,
      });

      console.log({ options });

      await kv.set(['challenges', options.challenge], { timeout: Date.now() + 60_000 } as Challenge);

      return new Response(JSON.stringify(options), {
        headers: { 'content-type': 'application/json' },
      });
    }

    case '/login/verify': {
      console.log(req.method, req.url);

      const json = await req.json();
      console.log({ json });

      const clientData = JSON.parse(atob(json.cred.response.clientDataJSON));
      console.log({ clientData });

      const userId = json.cred.response.userHandle;
      const user = await kv.get<User>(['users', userId]);
      if (!user.value) return new Response('Unauthorized', { status: 401 });
      console.log({ user });

      const challenge = await kv.get<Challenge>(['challenges', clientData.challenge]);
      if (!challenge.value || challenge.value.timeout < Date.now()) {
        return new Response('Challenge expired', { status: 400 });
      }

      const verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
        response: json.cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: 'http://localhost',
        expectedRPID: 'localhost',
        authenticator: user.value.credentials[json.cred.id],
      });

      if (verification.verified) {
        const { newCounter } = verification.authenticationInfo!;

        await kv.delete(['challenges', clientData.challenge]);

        await kv.set(['users', userId], {
          ...user.value,
          credentials: {
            ...user.value.credentials,
            [json.cred.id]: {
              ...user.value.credentials[json.cred.id],
              counter: newCounter,
            },
          },
        } as User);

        return new Response(JSON.stringify(verification), {
          headers: {
            'content-type': 'application/json',
            'set-cookie': `token=${await generateJWT(userId)}; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=${new Date(Date.now() + 600_000).toUTCString()}`,
          },
        });
      }

      return new Response('Unauthorized', { status: 401 });
    }

    case '/private': {
      console.log(req.method, req.url);

      const cookie = req.headers.get('cookie');
      const token = cookie?.split('=')[1];
      if (!token) return new Response('Unauthorized', { status: 401 });
      console.log({ token });

      const result = await verifyJWT(token);
      console.log({ result });

      const user = await kv.get<User>(['users', result.payload.userId as string]);
      if (!user.value) return new Response('Unauthorized', { status: 401 });

      return new Response(user.value.data);
    }

    default: {
      return new Response('Not found', { status: 404 });
    }
  }
};

Deno.serve({ port: 80, handler });
