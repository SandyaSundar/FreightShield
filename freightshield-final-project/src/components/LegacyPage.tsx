import { useEffect, useRef } from "react";
import { pages } from "@/legacy/pages.js";
import { emailPanel, socPanel } from "@/legacy/ai.js";
import { logisticsPage } from "@/legacy/logistics.js";
import type { SessionUser } from "@/store/permissions";

type LegacyPageName = keyof typeof pages;

export function LegacyPage({ page, user }: { page: LegacyPageName | "logistics"; user: SessionUser }) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    let cleanup: void | (() => void);
    let active = true;
    if (page === "logistics") {
      void import("leaflet").then((leaflet) => {
        if (!active) return;
        window.L = leaflet.default;
        cleanup = logisticsPage(element, user) || undefined;
      }).catch((error: unknown) => {
        element.textContent = error instanceof Error ? error.message : "The map could not be loaded.";
      });
    } else {
      const render = pages[page];
      if (render) render(element, user);
      else element.textContent = "This page is not available.";
    }

    return () => {
      active = false;
      cleanup?.();
      element.replaceChildren();
    };
  }, [page, user]);

  return <div ref={host} className="legacy-host" />;
}

export function legacyAgentPanel(which: "soc" | "email") {
  return which === "soc" ? socPanel() : emailPanel();
}