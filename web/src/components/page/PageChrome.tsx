import type { ElementType, ReactNode } from "react";
import { cn } from "../../lib/utils";

type PageHeaderProps = {
  eyebrow?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  metrics?: ReactNode;
  actions?: ReactNode;
  className?: string;
  copyClassName?: string;
  asideClassName?: string;
  titleAs?: ElementType;
};

type PageMetricPillProps = {
  label: ReactNode;
  dotClassName?: string;
  icon?: ReactNode;
  tone?: "default" | "muted" | "primary" | "success" | "warning" | "danger";
  className?: string;
};

type PageToolbarProps = {
  label?: ReactNode;
  className?: string;
  children: ReactNode;
};

type PageToolbarGroupProps = {
  className?: string;
  compact?: boolean;
  children: ReactNode;
};

const metricToneClasses: Record<NonNullable<PageMetricPillProps["tone"]>, string> = {
  default: "summary-pill",
  muted: "summary-pill-muted",
  primary: "bg-primary/10 text-primary",
  success: "bg-emerald-500/10 text-emerald-500",
  warning: "bg-amber-500/10 text-amber-500",
  danger: "bg-error/10 text-error",
};

export function PageHeader({
  eyebrow,
  title,
  description,
  metrics,
  actions,
  className,
  copyClassName,
  asideClassName,
  titleAs,
}: PageHeaderProps) {
  const TitleTag = titleAs || "h1";

  return (
    <div className={cn("page-header page-header-compact", className)}>
      <div className={cn("page-header-copy", copyClassName)}>
        {eyebrow ? <p className="page-eyebrow">{eyebrow}</p> : null}
        <TitleTag className="page-heading">{title}</TitleTag>
        {description ? <p className="page-subheading">{description}</p> : null}
      </div>

      {metrics || actions ? (
        <div className={cn("page-header-aside", asideClassName)}>
          {metrics ? <div className="page-header-metrics">{metrics}</div> : null}
          {actions ? <div className="page-header-actions">{actions}</div> : null}
        </div>
      ) : null}
    </div>
  );
}

export function PageMetricPill({
  label,
  dotClassName,
  icon,
  tone = "muted",
  className,
}: PageMetricPillProps) {
  return (
    <div className={cn("summary-pill-muted", metricToneClasses[tone], className)}>
      {dotClassName ? <span className={cn("h-1.5 w-1.5 rounded-full", dotClassName)} /> : null}
      {!dotClassName && icon ? <span className="inline-flex h-3.5 w-3.5 items-center justify-center">{icon}</span> : null}
      <span>{label}</span>
    </div>
  );
}

export function PageToolbar({ label, className, children }: PageToolbarProps) {
  return (
    <div className={cn("page-toolbar page-toolbar-compact", className)}>
      {label ? <div className="page-toolbar-copy">{label}</div> : null}
      <div className="page-toolbar-groups">{children}</div>
    </div>
  );
}

export function PageToolbarGroup({ className, compact = false, children }: PageToolbarGroupProps) {
  return (
    <div className={cn(compact ? "page-control-cluster" : "page-toolbar-group", className)}>
      {children}
    </div>
  );
}
