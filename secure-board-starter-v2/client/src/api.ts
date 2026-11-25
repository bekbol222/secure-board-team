let cachedCsrfToken: string | null = null;

async function getCsrfToken(forceRefresh = false): Promise<string> {
  if (cachedCsrfToken && !forceRefresh) {
    return cachedCsrfToken;
  }
  const res = await fetch("/api/auth/csrf");
  const data = await res.json().catch(() => ({}));
  if (!res.ok || typeof data.csrfToken !== "string") {
    throw new Error("CSRF 토큰을 가져오지 못했습니다.");
  }
  const token: string = data.csrfToken;
  cachedCsrfToken = token;
  return token;
}

export async function api<T = unknown>(path: string, method = "GET", body?: unknown): Promise<T> {
  const upperMethod = method.toUpperCase();
  const isStateChanging = !["GET", "HEAD", "OPTIONS"].includes(upperMethod);

  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (isStateChanging) {
    headers["X-CSRF-Token"] = await getCsrfToken();
  }

  let res = await fetch(path, {
    method: upperMethod,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  // If session was regenerated and token rotated, refresh token once and retry
  if (res.status === 403 && isStateChanging) {
    headers["X-CSRF-Token"] = await getCsrfToken(true);
    res = await fetch(path, {
      method: upperMethod,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
  }

  // Refresh cached CSRF token after login or logout since session ID changes
  if (res.ok && (path === "/api/auth/login" || path === "/api/auth/logout")) {
    cachedCsrfToken = null;
    await getCsrfToken(true).catch(() => {});
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.message ?? `요청 실패 (${res.status})`);
  }
  return data as T;
}

export async function uploadFile(postId: number, file: File): Promise<void> {
  const form = new FormData();
  form.append("postId", String(postId));
  form.append("file", file);

  const token = await getCsrfToken();
  let res = await fetch("/api/files/upload", {
    method: "POST",
    headers: { "X-CSRF-Token": token },
    body: form
  });

  if (res.status === 403) {
    const freshToken = await getCsrfToken(true);
    res = await fetch("/api/files/upload", {
      method: "POST",
      headers: { "X-CSRF-Token": freshToken },
      body: form
    });
  }

  if (!res.ok) {
    throw new Error("파일 업로드 실패");
  }
}

export function downloadUrl(storedName: string): string {
  return `/api/files/download?name=${encodeURIComponent(storedName)}`;
}