export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const param = url.searchParams.get("d");

    if (!param) {
      return new Response("Missing param", { status: 400 });
    } 

    const [encoded, sig] = param.split(".");

    if (!encoded || !sig) {
      return new Response("Bad format", { status: 400 });
    }

    // Verify signature
    const valid = await verifySignature(encoded, sig, env.SECRET_KEY);
    if (!valid) {
      return new Response("Invalid signature", { status: 403 });
    }

    // Decode target
    let targetUrl;
    try {
      const decoded = atob(encoded);
      targetUrl = new URL(decoded);
    } catch {
      return new Response("Invalid target", { status: 400 });
    }

    // 🔒 Allowlist
    const ALLOWED = [
      "httpbin.org",
      "kbsigmaboy67.github.io"
    ];

    if (!ALLOWED.includes(targetUrl.hostname)) {
      return new Response("Forbidden", { status: 403 });
    }

    // Proxy request
    const proxied = new Request(targetUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "follow"
    });

    proxied.headers.delete("host");

    const res = await fetch(proxied);

    const newRes = new Response(res.body, res);
    newRes.headers.set("Access-Control-Allow-Origin", "*");

    return newRes;
  }
};

// 🔐 HMAC verify
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

  const expected = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));

  return safeEqual(expected, signature);
}

// timing-safe compare
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) {
    res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return res === 0;
}
