declare module "*.js" {
  export const pages: Record<string, (element: HTMLElement, user: unknown) => unknown>;
  export function socPanel(): HTMLElement;
  export function emailPanel(): HTMLElement;
  export function logisticsPage(element: HTMLElement, user: { id: string | number; role: string }): (() => void) | void;
}