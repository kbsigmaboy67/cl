export default async function handler(req) {
  const url = new URL(req.url);
  const target = url.searchParams.get("url");

  // Strict allowlist
  const ALLOWED = [
    "api.github.com",
    "jsonplaceholder.typicode.com"
  ];

  if (!target) {
    return new Response("Missing url", { status: 400 });
  }

  const parsed = new URL(target);

  if (!ALLOWED.includes(parsed.hostname)) {
    return new Response("Domain not allowed", { status: 403 });
  }

  const resp = await fetch(parsed.toString(), {
    method: "GET",
    headers: {
      "User-Agent": "Fetch-Gateway"
    }
  });

  return new Response(resp.body, {
    status: resp.status,
    headers: {
      "Content-Type": resp.headers.get("content-type") || "text/plain",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
