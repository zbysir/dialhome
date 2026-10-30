import { api } from "./api";

/**
 * WebAuthn 的浏览器侧胶水（照 gerdr 的 ui/src/lib/passkey.ts）。
 *
 * 服务端（go-webauthn）用 base64url 传 challenge / credential id，浏览器 API 要 ArrayBuffer，返回的又是
 * ArrayBuffer —— 两个方向都得转。`PublicKeyCredential.toJSON()` 能省掉这段，但 Safari 18 才有。
 */

function fromB64u(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

function toB64u(b: ArrayBuffer): string {
  let s = "";
  for (const byte of new Uint8Array(b)) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const passkeySupported = () => typeof PublicKeyCredential !== "undefined" && !!navigator.credentials;

/**
 * 「人划掉的」和「浏览器不让做的」在错误对象上一模一样（都是 NotAllowedError，规范故意的）。唯一分得开的
 * 信号是时间：真弹出系统面板再让人划掉，最少大半秒；被策略挡掉是当场就回。快回来的不当取消，照旧报出来 ——
 * 吞成静默的话就是「点了没反应、而且查不出原因」。
 */
const CANCEL_MS = 700;

class Blocked extends Error {}

export function isCancel(e: unknown) {
  if (e instanceof Blocked) return false;
  const n = (e as { name?: string } | null)?.name;
  return n === "AbortError" || n === "NotAllowedError";
}

async function ask<T>(run: () => Promise<T>): Promise<T> {
  const t0 = performance.now();
  try {
    return await run();
  } catch (e) {
    if ((e as { name?: string }).name === "NotAllowedError" && performance.now() - t0 < CANCEL_MS) {
      throw new Blocked("浏览器没让做这次验证，而且不说原因。最常见的是这台设备上没有这个站点的 passkey，或者地址栏显示「不安全」。");
    }
    throw e;
  }
}

type Begin<T> = { options: { publicKey: T }; ceremony: string };
type CreateJSON = { challenge: string; user: { id: string; name: string; displayName: string }; excludeCredentials?: { id: string; type: string }[] };
type RequestJSON = { challenge: string; allowCredentials?: { id: string; type: string }[] };

/** 注册一把 passkey。kind = setup（init 链接，带令牌）或 add（已登录，再加一把）。 */
export async function registerPasskey(kind: "setup" | "add", token?: string): Promise<void> {
  const base = kind === "setup" ? "/setup" : "/passkeys";
  const { options, ceremony } = await api.step<Begin<CreateJSON>>(base + "/begin", kind === "setup" ? { token } : undefined);
  const pk = options.publicKey;
  const req = {
    ...pk,
    challenge: fromB64u(pk.challenge),
    user: { ...pk.user, id: fromB64u(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({ ...c, id: fromB64u(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  const cred = (await ask(() => navigator.credentials.create({ publicKey: req }))) as PublicKeyCredential | null;
  if (!cred) throw new Error("没拿到 passkey");
  const r = cred.response as AuthenticatorAttestationResponse;
  await api.step(
    base + "/finish",
    JSON.stringify({
      id: cred.id,
      rawId: toB64u(cred.rawId),
      type: cred.type,
      response: { clientDataJSON: toB64u(r.clientDataJSON), attestationObject: toB64u(r.attestationObject) },
    }),
    ceremony,
  );
}

export async function loginPasskey(): Promise<void> {
  const { options, ceremony } = await api.step<Begin<RequestJSON>>("/login/begin");
  const pk = options.publicKey;
  const req = {
    ...pk,
    challenge: fromB64u(pk.challenge),
    allowCredentials: (pk.allowCredentials ?? []).map((c) => ({ ...c, id: fromB64u(c.id) })),
  } as unknown as PublicKeyCredentialRequestOptions;
  const cred = (await ask(() => navigator.credentials.get({ publicKey: req }))) as PublicKeyCredential | null;
  if (!cred) throw new Error("没拿到 passkey");
  const r = cred.response as AuthenticatorAssertionResponse;
  await api.step(
    "/login/finish",
    JSON.stringify({
      id: cred.id,
      rawId: toB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: toB64u(r.clientDataJSON),
        authenticatorData: toB64u(r.authenticatorData),
        signature: toB64u(r.signature),
        userHandle: r.userHandle ? toB64u(r.userHandle) : null,
      },
    }),
    ceremony,
  );
}
