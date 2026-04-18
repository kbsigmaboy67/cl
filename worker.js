export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const param = url.searchParams.get("d");

      if (!param) {
        return new Response("Missing param", { status: 400 });
      }

      const parts = param.split(".");
      if (parts.length !== 2) {
        return new Response("Bad format", { status: 400 });
      }

      const [encoded, sig] = parts;

      if (!env.SECRET_KEY) {
        return new Response("Server misconfigured (no secret)", { status: 500 });
      }

      const valid = await verifySignature(encoded, sig, env.SECRET_KEY);
      if (!valid) {
        return new Response("Invalid signature", { status: 403 });
      }

      let decoded;
      try {
        decoded = atob(encoded);
      } catch {
        return new Response("Bad base64", { status: 400 });
      }

      let target;
      try {
        target = new URL(decoded);
      } catch {
        return new Response("Invalid URL", { status: 400 });
      }

      const ALLOWED = ["httpbin.org", "kbsigmaboy67.github.io"];

      if (!ALLOWED.includes(target.hostname)) {
        return new Response("Forbidden", { status: 403 });
      }

      const res = await fetch(target.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body
      });

      return new Response(res.body, {
        status: res.status,
        headers: {
          "Access-Control-Allow-Origin": "*"
        }
      });

    } catch (err) {
      return new Response("Worker error: " + err.message, {
        status: 500
      });
    }
  }
};

async function verifySignature(data, signature, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sigBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  const expected = btoa(
    String.fromCharCode(...new Uint8Array(sigBuffer))
  );

  return expected === signature;
}
