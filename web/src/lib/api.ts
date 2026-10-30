/** 调后台的接口。全部在同一个 origin 上，cookie 是 HttpOnly + SameSite=Strict，这里不碰它。 */

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function call<T>(method: string, path: string, body?: unknown, query = ""): Promise<T> {
  const r = await fetch("/api" + path + query, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError((data as { error?: string }).error || `请求失败（${r.status}）`, r.status);
  return data as T;
}

export type State = { loggedIn: boolean; hasPasskey: boolean; domain: string };
export type Online = { since: string; addr: string };
export type Host = { name: string; created: string; online: Online | null };
export type PendingInvite = { host: string; expires: string };
export type Hosts = { relay: string; hosts: Host[]; invites: PendingInvite[] };
export type Invite = { host: string; code: string; relay: string; expires: string; replaces: boolean };
export type Passkey = { id: string; label: string; created: string; lastUsed: string; current: boolean };

export const api = {
  state: () => call<State>("GET", "/state"),
  logout: () => call("POST", "/logout"),
  hosts: () => call<Hosts>("GET", "/hosts"),
  invite: (host: string) => call<Invite>("POST", "/invites", { host }),
  revokeInvite: (host: string) => call("DELETE", "/invites/" + encodeURIComponent(host)),
  removeHost: (host: string) => call("DELETE", "/hosts/" + encodeURIComponent(host)),
  passkeys: () => call<Passkey[]>("GET", "/passkeys"),
  deletePasskey: (id: string) => call("DELETE", "/passkeys/" + encodeURIComponent(id)),
  /** passkey 那几步：begin 拿 options，finish 把浏览器的回答原样交回去（ceremony 走 query） */
  step: <T,>(path: string, body?: unknown, ceremony?: string) =>
    call<T>("POST", path, body, ceremony ? "?ceremony=" + encodeURIComponent(ceremony) : ""),
};
