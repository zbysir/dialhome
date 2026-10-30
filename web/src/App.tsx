import { useCallback, useEffect, useState } from "react";
import { KeyRound, Loader2, LogOut } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";
import { Dashboard } from "@/components/Dashboard";
import { api, type State } from "@/lib/api";
import { isCancel, loginPasskey, passkeySupported, registerPasskey } from "@/lib/passkey";

/** `dialhome admin init` 印出来的链接是 https://<域名>/#setup=<令牌>。令牌在 # 后面：不进请求、不进日志。 */
function setupToken() {
  return new URLSearchParams(location.hash.slice(1)).get("setup") ?? "";
}

export function App() {
  const [state, setState] = useState<State | null>(null);
  const [err, setErr] = useState("");
  const [token, setToken] = useState(setupToken);

  const refresh = useCallback(() => {
    api.state().then(setState, (e: Error) => setErr(e.message));
  }, []);
  useEffect(refresh, [refresh]);

  const logout = async () => {
    await api.logout().catch(() => {});
    refresh();
  };

  if (err) return <Center><p className="text-bad">{err}</p></Center>;
  if (!state) {
    return (
      <Center>
        <Loader2 className="size-5 animate-spin text-muted-foreground" />
      </Center>
    );
  }

  let body;
  if (token) {
    body = (
      <Setup
        token={token}
        done={() => {
          history.replaceState(null, "", location.pathname);
          setToken("");
          refresh();
        }}
      />
    );
  } else if (!state.loggedIn) {
    body = <Login state={state} done={refresh} />;
  } else {
    body = <Dashboard domain={state.domain} onExpired={refresh} />;
  }

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-10 border-b bg-background/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-3xl items-center gap-3 px-4">
          <img src="/favicon.svg" alt="" className="size-7" />
          <div className="flex min-w-0 flex-col leading-tight">
            <span className="font-semibold">dialhome</span>
            <span className="truncate font-mono text-xs text-muted-foreground">{state.domain}</span>
          </div>
          <div className="flex-1" />
          {state.loggedIn && !token && (
            <Button variant="ghost" size="sm" onClick={logout}>
              <LogOut />
              退出
            </Button>
          )}
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-4 py-6">{body}</main>
      <Toaster position="top-center" />
    </div>
  );
}

function Center({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-screen items-center justify-center p-6">{children}</div>;
}

/** 登录 / 注册那一屏都是同一张居中的卡片。 */
function Gate({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto mt-[12vh] max-w-sm rounded-xl border bg-card p-6 text-center shadow-sm">
      <div className="mx-auto mb-4 flex size-11 items-center justify-center rounded-full bg-muted">
        <KeyRound className="size-5 text-brand" />
      </div>
      <h1 className="mb-2 text-base font-semibold">{title}</h1>
      {children}
    </div>
  );
}

function usePasskeyAction(run: () => Promise<void>, done: () => void) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const go = async () => {
    setBusy(true);
    setMsg("");
    try {
      await run();
      done();
    } catch (e) {
      if (!isCancel(e)) setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return { busy, msg, go };
}

function Login({ state, done }: { state: State; done: () => void }) {
  const { busy, msg, go } = usePasskeyAction(loginPasskey, done);
  if (!state.hasPasskey) {
    return (
      <Gate title="还没有管理员">
        <p className="text-sm text-muted-foreground">在中继那台服务器上运行下面这条，用它印出来的链接注册一把 passkey：</p>
        <pre className="mt-4 rounded-md bg-muted px-3 py-2 text-left font-mono text-xs">dialhome admin init</pre>
      </Gate>
    );
  }
  return (
    <Gate title="管理后台">
      <p className="mb-5 text-sm text-muted-foreground">用管理员的 passkey 登录。</p>
      <Button className="w-full" onClick={go} disabled={busy || !passkeySupported()}>
        {busy ? <Loader2 className="animate-spin" /> : <KeyRound />}用 passkey 登录
      </Button>
      {!passkeySupported() && <p className="mt-3 text-xs text-bad">这个浏览器不支持 passkey。</p>}
      {msg && <p className="mt-3 text-left text-xs text-bad">{msg}</p>}
    </Gate>
  );
}

function Setup({ token, done }: { token: string; done: () => void }) {
  const { busy, msg, go } = usePasskeyAction(
    () => registerPasskey("setup", token),
    () => {
      toast.success("passkey 注册好了，以后就用它登录");
      done();
    },
  );
  return (
    <Gate title="注册管理员 passkey">
      <p className="mb-5 text-sm text-muted-foreground">
        这个链接是 <code className="font-mono">dialhome admin init</code> 出的，只能用一次。注册完就用这台设备的 passkey 登录后台。
      </p>
      <Button className="w-full" onClick={go} disabled={busy || !passkeySupported()}>
        {busy ? <Loader2 className="animate-spin" /> : <KeyRound />}注册 passkey
      </Button>
      {msg && <p className="mt-3 text-left text-xs text-bad">{msg}</p>}
    </Gate>
  );
}
