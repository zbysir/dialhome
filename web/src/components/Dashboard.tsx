import { useCallback, useEffect, useState } from "react";
import { Check, Copy, KeyRound, Loader2, Plus, Server, Ticket, Trash2, TriangleAlert, X } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { ApiError, api, type Hosts, type Invite, type Passkey } from "@/lib/api";
import { isCancel, registerPasskey } from "@/lib/passkey";
import { ago, date, left } from "@/lib/time";
import { cn } from "@/lib/utils";

/** 隔多久刷一次在线状态。页面藏着时不刷（document.hidden）。 */
const POLL_MS = 10_000;

export function Dashboard({ domain, onExpired }: { domain: string; onExpired: () => void }) {
  // 会话过期（401）就退回登录页，别在每个按钮上各报一遍
  const guard = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) onExpired();
      else toast.error((e as Error).message);
    },
    [onExpired],
  );

  return (
    <div className="flex flex-col gap-6">
      <HostsSection domain={domain} guard={guard} />
      <PasskeysSection guard={guard} />
    </div>
  );
}

function Section({ icon, title, extra, children }: { icon: React.ReactNode; title: string; extra?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border bg-card">
      <div className="flex items-center gap-2 border-b px-4 py-3">
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
        <h2 className="text-sm font-semibold">{title}</h2>
        <div className="flex-1" />
        {extra}
      </div>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ 主机 */

function HostsSection({ domain, guard }: { domain: string; guard: (e: unknown) => void }) {
  const [data, setData] = useState<Hosts | null>(null);
  const [inviting, setInviting] = useState(false);
  const [issued, setIssued] = useState<Invite | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [, tick] = useState(0);

  const load = useCallback(() => api.hosts().then(setData, guard), [guard]);
  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (!document.hidden) {
        load();
        tick((n) => n + 1); // 顺带刷新「几分钟前」「还剩几分钟」
      }
    }, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const remove = async (host: string) => {
    try {
      await api.removeHost(host);
      toast.success(`删掉了 ${host}`);
      load();
    } catch (e) {
      guard(e);
    }
  };
  const revoke = async (host: string) => {
    try {
      await api.revokeInvite(host);
      if (issued?.host === host) setIssued(null);
      load();
    } catch (e) {
      guard(e);
    }
  };

  const online = data?.hosts.filter((h) => h.online).length ?? 0;

  return (
    <Section
      icon={<Server />}
      title="主机"
      extra={
        <>
          {data && (
            <span className="mr-2 text-xs text-muted-foreground">
              {online} / {data.hosts.length} 在线
            </span>
          )}
          {!inviting && (
            <Button size="sm" onClick={() => setInviting(true)}>
              <Plus />
              邀请主机
            </Button>
          )}
        </>
      }
    >
      {inviting && (
        <InviteForm
          domain={domain}
          onCancel={() => setInviting(false)}
          onIssued={(iv) => {
            setIssued(iv);
            setInviting(false);
            load();
          }}
          guard={guard}
        />
      )}
      {issued && <IssuedInvite invite={issued} onClose={() => setIssued(null)} />}

      {!data ? (
        <div className="flex justify-center py-10">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      ) : data.hosts.length === 0 && data.invites.length === 0 ? (
        <p className="px-4 py-10 text-center text-sm text-muted-foreground">还没有主机。点「邀请主机」出一个邀请码，在那台机器上 join。</p>
      ) : (
        <ul className="divide-y">
          {data.hosts.map((h) => (
            <li key={h.name} className="flex items-center gap-3 px-4 py-3">
              <span className={cn("size-2 shrink-0 rounded-full", h.online ? "bg-ok" : "bg-muted-foreground/40")} />
              <div className="min-w-0 flex-1">
                <a href={`https://${h.name}/`} target="_blank" rel="noreferrer" className="truncate font-mono text-sm hover:underline">
                  {h.name}
                </a>
                <p className="truncate text-xs text-muted-foreground">
                  {h.online ? `在线 · 连上 ${ago(h.online.since)} · ${h.online.addr}` : `离线 · 注册于 ${date(h.created)}`}
                </p>
              </div>
              <Button variant="ghost" size="icon-sm" title="删除" onClick={() => setRemoving(h.name)}>
                <Trash2 />
              </Button>
            </li>
          ))}
          {data.invites.map((iv) => (
            <li key={"iv:" + iv.host + iv.expires} className="flex items-center gap-3 px-4 py-3">
              <Ticket className="size-4 shrink-0 text-warn" />
              <div className="min-w-0 flex-1">
                <span className="truncate font-mono text-sm">{iv.host}</span>
                <p className="text-xs text-muted-foreground">邀请码待用 · {left(iv.expires)}</p>
              </div>
              <Button variant="ghost" size="sm" onClick={() => revoke(iv.host)}>
                作废
              </Button>
            </li>
          ))}
        </ul>
      )}

      <AlertDialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删掉 {removing}？</AlertDialogTitle>
            <AlertDialogDescription>
              它的隧道会马上断开，从外面就打不开这台机器了。要再连上，得重新出一个邀请码、在那台机器上再 join 一次。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction className="bg-destructive text-white hover:bg-destructive/90" onClick={() => removing && remove(removing)}>
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Section>
  );
}

function InviteForm({
  domain,
  onCancel,
  onIssued,
  guard,
}: {
  domain: string;
  onCancel: () => void;
  onIssued: (iv: Invite) => void;
  guard: (e: unknown) => void;
}) {
  const [host, setHost] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    try {
      onIssued(await api.invite(host));
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setMsg(err.message);
      else guard(err);
    } finally {
      setBusy(false);
    }
  };
  // 例子按中继自己的域名往下挂一层：relay.example.com → mac.example.com
  const zone = domain.includes(".") ? domain.slice(domain.indexOf(".") + 1) : domain;
  return (
    <form onSubmit={submit} className="border-b bg-muted/40 px-4 py-4">
      <label className="mb-1.5 block text-xs font-medium text-muted-foreground" htmlFor="host">
        主机名（手机上打开的那个地址）
      </label>
      <div className="flex gap-2">
        <Input
          id="host"
          autoFocus
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder={`mac.${zone}`}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          className="font-mono"
        />
        <Button type="submit" disabled={busy || !host.trim()}>
          {busy && <Loader2 className="animate-spin" />}出邀请码
        </Button>
        <Button type="button" variant="ghost" size="icon" onClick={onCancel} title="取消">
          <X />
        </Button>
      </div>
      {msg ? (
        <p className="mt-2 text-xs text-bad">{msg}</p>
      ) : (
        <p className="mt-2 text-xs text-muted-foreground">DNS 上要有一条这个名字指向中继这台 VPS 的 A 记录，手机才连得过来。</p>
      )}
    </form>
  );
}

/** 刚出的邀请码：只这一次看得到（服务端只存哈希），所以把要敲的命令整条摆出来。 */
function IssuedInvite({ invite, onClose }: { invite: Invite; onClose: () => void }) {
  const [app, setApp] = useState<"herdr-web" | "gerdr">("herdr-web");
  const cmd =
    app === "herdr-web"
      ? `herdr-web relay join ${invite.relay} ${invite.host} ${invite.code}`
      : `gerdr remote join ${invite.relay} ${invite.host} ${invite.code}`;
  return (
    <div className="border-b px-4 py-4">
      <div className="mb-3 flex items-start gap-2">
        <div className="flex-1">
          <p className="text-sm font-medium">
            给 <span className="font-mono">{invite.host}</span> 的邀请码
          </p>
          <p className="text-xs text-muted-foreground">只显示这一次 · 用一次就废 · {left(invite.expires)}</p>
        </div>
        <Button variant="ghost" size="icon-sm" onClick={onClose} title="收起">
          <X />
        </Button>
      </div>
      {invite.replaces && (
        <p className="mb-3 flex gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs">
          <TriangleAlert className="mt-px size-3.5 shrink-0 text-warn" />
          这个名字已经有主机了。码一用掉就会顶掉原来那台（重装系统丢了钥匙时就靠这个认领回来）。
        </p>
      )}
      <CopyRow label="邀请码" value={invite.code} />
      <div className="mt-3 mb-1.5 flex items-center gap-1">
        <span className="mr-1 text-xs text-muted-foreground">在那台机器上敲：</span>
        {(["herdr-web", "gerdr"] as const).map((a) => (
          <Badge
            key={a}
            asChild
            variant={app === a ? "secondary" : "outline"}
            className={cn("cursor-pointer", app !== a && "text-muted-foreground")}
          >
            <button type="button" onClick={() => setApp(a)}>
              {a}
            </button>
          </Badge>
        ))}
      </div>
      <CopyRow value={cmd} />
    </div>
  );
}

function CopyRow({ label, value }: { label?: string; value: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      toast.error("复制不了，手动选中复制吧");
    }
  };
  return (
    <div className="flex items-center gap-2 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
      {label && <span className="shrink-0 text-xs text-muted-foreground">{label}</span>}
      <code className="min-w-0 flex-1 overflow-x-auto font-mono text-xs whitespace-nowrap select-all">{value}</code>
      <Button variant="ghost" size="icon-sm" onClick={copy} title="复制">
        {done ? <Check className="text-ok" /> : <Copy />}
      </Button>
    </div>
  );
}

/* ------------------------------------------------------------------ passkey */

function PasskeysSection({ guard }: { guard: (e: unknown) => void }) {
  const [keys, setKeys] = useState<Passkey[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<Passkey | null>(null);

  const load = useCallback(() => api.passkeys().then(setKeys, guard), [guard]);
  useEffect(() => {
    load();
  }, [load]);

  const add = async () => {
    setAdding(true);
    try {
      await registerPasskey("add");
      toast.success("加好了，这台设备也能登录后台了");
      load();
    } catch (e) {
      if (!isCancel(e)) guard(e);
    } finally {
      setAdding(false);
    }
  };
  const del = async (k: Passkey) => {
    try {
      await api.deletePasskey(k.id);
      toast.success(`删掉了 ${k.label}`);
      load();
    } catch (e) {
      guard(e);
    }
  };

  return (
    <Section
      icon={<KeyRound />}
      title="管理员 passkey"
      extra={
        <Button size="sm" variant="outline" onClick={add} disabled={adding}>
          {adding ? <Loader2 className="animate-spin" /> : <Plus />}
          在这台设备上添加
        </Button>
      }
    >
      {!keys ? (
        <div className="flex justify-center py-8">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <ul className="divide-y">
          {keys.map((k) => (
            <li key={k.id} className="flex items-center gap-3 px-4 py-3">
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-2 text-sm">
                  {k.label}
                  {k.current && <Badge variant="secondary">当前</Badge>}
                </p>
                <p className="text-xs text-muted-foreground">
                  添加于 {date(k.created)} · 上次用 {ago(k.lastUsed)}
                </p>
              </div>
              <Button variant="ghost" size="icon-sm" title="删除" onClick={() => setDeleting(k)} disabled={keys.length === 1}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      )}
      <p className="border-t px-4 py-3 text-xs text-muted-foreground">
        passkey 全丢了：在服务器上 <code className="font-mono">dialhome admin reset</code> 清掉，再 <code className="font-mono">dialhome admin init</code> 注册新的。
      </p>

      <AlertDialog open={!!deleting} onOpenChange={(o) => !o && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删掉「{deleting?.label}」？</AlertDialogTitle>
            <AlertDialogDescription>
              这把 passkey 以后登录不了后台，用它登着的会话也会马上退出{deleting?.current ? "（就是你现在这个）" : ""}。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction className="bg-destructive text-white hover:bg-destructive/90" onClick={() => deleting && del(deleting)}>
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Section>
  );
}
