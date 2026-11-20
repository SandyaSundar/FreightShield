import { createFileRoute } from "@tanstack/react-router";
import { OperationsShell } from "@/components/OperationsShell";
import { ROUTES } from "@/store/permissions";

export const Route = createFileRoute("/$page")({
  head: ({ params }) => {
    const label = params.page === "logistics"
      ? "Freight logistics simulation"
      : ROUTES.find((item) => item.id === params.page)?.label || "Security Operations";
    const title = `${label} | FreightShield SOC`;
    const description = `${label} in the FreightShield security operations center.`;
    return { meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ] };
  },
  component: PageRoute,
});

function PageRoute() {
  const { page } = Route.useParams();
  return <OperationsShell page={page} />;
}