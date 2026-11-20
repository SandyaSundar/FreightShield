import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Activity, Bell, Bot, ChevronRight, ClipboardList, LogOut, Menu, Moon, RefreshCw, Shield, ShieldCheck, Sun } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { api, checkHealth, explain } from "@/api/client";
import { LegacyPage, legacyAgentPanel } from "@/components/LegacyPage";
import { useAuth } from "@/store/auth";
import { can, homeFor, visibleRoutes } from "@/store/permissions";

const LIVE_PAGES = new Set(["dashboard", "alerts", "agents", "incidents", "detections", "vendor-alerts", "vendor-agents", "vendor-detections", "response", "vendor-response"]);

function unreadCount(data: unknown) {
  return typeof data === "object" && data !== null && "unread" in data ? Number(data.unread) || 0 : 0;
}

export function OperationsShell({ page }: { page: string }) {
  const { user, ready, signOut } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [compact, setCompact] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [theme, setTheme] = useState("dark");
  const [refreshKey, setRefreshKey] = useState(0);
  const [health, setHealth] = useState("API · CONNECTING");
  const [bellCount, setBellCount] = useState<number | null>(null);
  const [bellOpen, setBellOpen] = useState(false);
  const [notifications, setNotifications] = useState<Array<{ id: number; title: string; severity: string; ts?: string }>>([]);
  const [agentPanel, setAgentPanel] = useState<"soc" | "email" | null>(null);
  const [panelContent, setPanelContent] = useState<HTMLElement | null>(null);
  const seenMax = useRef<number | null>(null);
  const routes = useMemo(() => visibleRoutes(user), [user]);
  const title = routes.find((route) => route.id === page)?.label || "FreightShield SOC";
  const notificationBase = user?.role === "vendor" ? "/vendor/notifications" : user && can(user, "notifications:read") ? "/notifications" : null;
  const authorized = Boolean(user && routes.some((route) => route.id === page));
  const isAiAllowed = user ? can(user, "ai:use") : false;

  useEffect(() => {
    const savedTheme = localStorage.getItem("freightshield-theme") || "dark";
    setTheme(savedTheme);
    document.documentElement.dataset["theme"] = savedTheme;
  }, []);

  useEffect(() => {
    if (!ready || user || page === "") return;
    void navigate({ to: "/", replace: true });
  }, [navigate, page, ready, user]);

  useEffect(() => {
    if (!ready || !user) return;
    if (!authorized) {
      void navigate({ to: "/$page", params: { page: homeFor(user) }, replace: true });
    }
  }, [authorized, navigate, ready, user]);

  useEffect(() => {
    let active = true;
    const pollHealth = async () => {
      try {
        const result = await checkHealth();
        if (active) setHealth(`API · ${result.environment || result.status}`);
      } catch {
        if (active) setHealth("API · OFFLINE");
      }
    };
    void pollHealth();
    const timer = window.setInterval(() => { if (!document.hidden) void pollHealth(); }, 60_000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!notificationBase) return;
    let active = true;
    const poll = async () => {
      if (document.hidden) return;
      try {
        const [summary, result] = await Promise.all([
          api<{ unread: number; unread_by_severity?: Record<string, number> }>(`${notificationBase}/summary`),
          api<{ items: Array<{ id: number; title: string; severity: string; ts?: string }> }>(`${notificationBase}?limit=5&read=false`),
        ]);
        if (!active) return;
        setBellCount(unreadCount(summary));
        setNotifications(result.items || []);
        const newest = (result.items || []).reduce((max, item) => Math.max(max, item.id), 0);
        if (seenMax.current !== null) {
          result.items?.filter((item) => item.id > (seenMax.current || 0) && ["critical", "high"].includes(item.severity))
            .reverse().forEach((item) => toast(`${item.severity.toUpperCase()}: ${item.title}`, { className: `toast-${item.severity}` }));
        }
        seenMax.current = Math.max(seenMax.current || 0, newest);
      } catch (error) {
        if (active && !(error instanceof Error)) toast.error(explain(error));
      }
    };
    void poll();
    const timer = window.setInterval(() => { if (!document.hidden) void poll(); }, 30_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [notificationBase]);

  useEffect(() => {
    if (!LIVE_PAGES.has(page)) return;
    const timer = window.setInterval(() => {
      if (!document.hidden && !document.querySelector(".drawer.open") && !document.activeElement?.matches("input,textarea,select")) {
        void queryClient.invalidateQueries({ queryKey: ["api"] });
        setRefreshKey((value) => value + 1);
      }
    }, 30_000);
    return () => window.clearInterval(timer);
  }, [page, queryClient]);

  useEffect(() => {
    if (!agentPanel) {
      setPanelContent(null);
      return;
    }
    setPanelContent(legacyAgentPanel(agentPanel));
  }, [agentPanel]);

  const logout = async () => {
    await queryClient.cancelQueries();
    queryClient.clear();
    try {
      await signOut();
    } catch (error) {
      toast.error(explain(error));
    } finally {
      void navigate({ to: "/", replace: true });
    }
  };

  const setColorTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset["theme"] = next;
    window.localStorage.setItem("freightshield-theme", next);
    setTheme(next);
  };

  const openRoute = (routeId: string) => {
    setMobileNav(false);
    void navigate({ to: "/$page", params: { page: routeId } });
  };

  if (!ready || !user || !authorized) {
    return <div className="session-loading" aria-live="polite"><div className="loading-mark"><Shield /></div><span>{ready ? "Returning to sign-in…" : "Restoring secure session…"}</span></div>;
  }

  const groups = [...new Set(routes.map((route) => route.group))];
  const navigation = (
    <>
      <div className="sidebar-identity"><div className="identity-avatar">{(user.name || user.email || "F").slice(0, 1).toUpperCase()}</div><div><strong>{user.role_label}</strong><span>AUTHORIZED ACCOUNT</span></div></div>
      <nav aria-label="Primary navigation" className="sidebar-nav">
        {groups.map((group) => (
          <section className="nav-group" key={group}>
            <h2>{group}</h2>
            {routes.filter((route) => route.group === group).map((route) => (
              <button key={route.id} type="button" className={`nav-link ${route.id === page ? "active" : ""}`} aria-current={route.id === page ? "page" : undefined} onClick={() => openRoute(route.id)}>
                <span className="nav-marker" aria-hidden="true" />{route.label}{route.id === "logistics" && <span className="nav-sim">SIM</span>}
              </button>
            ))}
          </section>
        ))}
      </nav>
      <div className="sidebar-foot"><span className="secure-mark"><ShieldCheck size={15} /> SESSION SECURE</span><span>FreightShield SOC · Phase 10</span></div>
    </>
  );

  return (
    <div className={`soc-shell ${compact ? "sidebar-collapsed" : ""}`}>
      <header className="topbar">
        <Button className="sidebar-toggle" variant="ghost" size="icon" onClick={() => setCompact((value) => !value)} aria-label={compact ? "Expand navigation" : "Collapse navigation"} title={compact ? "Expand navigation" : "Collapse navigation"}><Menu /></Button>
        <Button className="mobile-menu" variant="ghost" size="icon" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu /></Button>
        <Link className="top-brand" to="/"><span className="brand-mark"><ShieldCheck /></span><span>FREIGHT<span className="brand-light">SHIELD</span></span></Link>
        <div className="top-divider" />
        <div className="top-context"><span>SECURITY OPERATIONS</span><strong>{title}</strong></div>
        <div className="top-actions">
          {isAiAllowed && <>
            <Button className="ai-action ai-primary" onClick={() => setAgentPanel("soc")}><Bot /> <span>AI SOC Investigator</span></Button>
            <Button className="ai-action" variant="outline" onClick={() => setAgentPanel("email")}><ClipboardList /> <span>AI Email Router</span></Button>
          </>}
          <span className={`api-indicator ${health.includes("OFFLINE") ? "offline" : ""}`}><span />{health}</span>
          {notificationBase && <div className="notification-wrap">
            <Button variant="ghost" size="icon" aria-label={`Notifications${bellCount === null ? "" : `, ${bellCount} unread`}`} aria-expanded={bellOpen} onClick={() => setBellOpen((value) => !value)}><Bell /><span className="bell-count">{bellCount ?? "—"}</span></Button>
            {bellOpen && <div className="notification-menu" role="dialog" aria-label="Unread notifications"><div className="notification-menu-head"><strong>Unread alerts</strong><span>{bellCount ?? 0} unread</span></div>{notifications.length ? notifications.map((notice) => <button type="button" key={notice.id} onClick={() => { setBellOpen(false); openRoute(user.role === "vendor" ? "vendor-notifications" : "notifications"); }}><span className={`severity-dot ${notice.severity}`} /><span>{notice.title}</span><small>{notice.severity}</small></button>) : <p>No unread notifications.</p>}<button type="button" className="all-notifications" onClick={() => { setBellOpen(false); openRoute(user.role === "vendor" ? "vendor-notifications" : "notifications"); }}>Open notifications <ChevronRight size={14} /></button></div>}
          </div>}
          <Button variant="ghost" size="icon" onClick={setColorTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title="Change appearance">{theme === "dark" ? <Sun /> : <Moon />}</Button>
          <div className="top-account"><span className="account-dot" /> <span>{user.name || user.email}</span><b>{user.role_label}</b></div>
          <Button variant="ghost" size="sm" onClick={() => void logout()} aria-label="Sign out"><LogOut /> <span className="signout-text">Sign out</span></Button>
        </div>
      </header>
      <aside className="desktop-sidebar" aria-label="Security operations navigation">{navigation}</aside>
      <main className="soc-main">
        <div className="page-topline"><div><p className="page-kicker">{routes.find((route) => route.id === page)?.group.toUpperCase()}</p><h1>{title}</h1></div><Button variant="outline" size="icon" aria-label="Refresh current page" title="Refresh" onClick={() => { void queryClient.invalidateQueries({ queryKey: ["api"] }); setRefreshKey((value) => value + 1); }}><RefreshCw /></Button></div>
        <div className="page-rule" />
        <LegacyPage key={`${page}-${refreshKey}`} page={page as Parameters<typeof LegacyPage>[0]["page"]} user={user} />
        <footer className="workspace-footer"><span><Activity size={13} /> SYSTEMS OPERATIONAL</span><span>DATA PROVIDED BY FREIGHTSHIELD API</span></footer>
      </main>
      <Sheet open={mobileNav} onOpenChange={setMobileNav}><SheetContent side="left" className="mobile-sidebar"><SheetTitle className="sr-only">Security operations navigation</SheetTitle><div className="brand mobile-lockup"><span className="brand-mark"><ShieldCheck /></span><span>FREIGHTSHIELD</span></div>{navigation}</SheetContent></Sheet>
      <Sheet open={agentPanel !== null} onOpenChange={(open) => { if (!open) setAgentPanel(null); }}><SheetContent side="right" className="agent-sheet"><SheetTitle>{agentPanel === "soc" ? "AI SOC Investigator" : "AI Email Router"}</SheetTitle>{panelContent && <div className="agent-panel-mount" ref={(node) => { if (node && panelContent.parentElement !== node) node.append(panelContent); }} />}</SheetContent></Sheet>
      <span className="sr-only">{health}</span>
    </div>
  );
}