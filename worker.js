export default {
  async fetch(request) {
    const url = new URL(request.url);

    const encodedTarget = url.searchParams.get("u");

    if (!encodedTarget) {
      return new Response("Missing target (?u=)", { status: 400 });
    }

    let targetUrl;

    try {
      targetUrl = new URL(atob(encodedTarget));
    } catch {
      return new Response("Invalid encoded URL", { status: 400 });
    }

    // Fetch upstream
    const upstreamResponse = await fetch(targetUrl.toString(), {
      method: request.method,
      headers: filterHeaders(request.headers),
      body: request.body,
      redirect: "follow"
    });

    const contentType = upstreamResponse.headers.get("content-type") || "";

    // Clone headers so we can modify safely
    const headers = new Headers(upstreamResponse.headers);

    // Remove security policies that break proxies
    headers.delete("content-security-policy");
    headers.delete("content-security-policy-report-only");
    headers.delete("x-frame-options");

    // If HTML → rewrite
    if (contentType.includes("text/html")) {
      let html = await upstreamResponse.text();

      const base = targetUrl.origin;

      html = rewriteHtml(html, base);

      headers.set("content-type", "text/html; charset=utf-8");

      return new Response(html, {
        status: upstreamResponse.status,
        headers
      });
    }

    // Non-HTML (JS, CSS, images, etc.)
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers
    });
  }
};

/**
 * Rewrites HTML so ALL navigation stays inside proxy
 */
function rewriteHtml(html, base) {
  return html

    // src="..."
    .replace(/src="\/\//g, 'src="https://')

    // href="..."
    .replace(/href="\/\//g, 'href="https://')

    // absolute src
    .replace(/src="https?:\/\/([^"]+)"/g, (m, p1) => {
      return `src="?u=${btoa("https://" + p1)}"`;
    })

    // absolute href
    .replace(/href="https?:\/\/([^"]+)"/g, (m, p1) => {
      return `href="?u=${btoa("https://" + p1)}"`;
    })

    // forms
    .replace(/action="https?:\/\/([^"]+)"/g, (m, p1) => {
      return `action="?u=${btoa("https://" + p1)}"`;
    })

    // inject <base> to help relative paths
    .replace(
      "<head>",
      `<head><base href="${base}/">`
    );
}

/**
 * Removes headers that break proxy rendering
 */
function filterHeaders(headers) {
  const newHeaders = new Headers(headers);

  newHeaders.delete("cookie"); // optional (privacy + avoids session leaks)
  newHeaders.delete("referer");

  return newHeaders;
}
