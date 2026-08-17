"use client";

import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CalendarClock,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Download,
  FileSearch,
  Gauge,
  History,
  Menu,
  Network,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { ChangeEvent, DragEvent, Fragment, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

type View = "dashboard" | "changes" | "search" | "manual" | "settings";
type Segment = { id: string; name: string; cidrs: string; enabled: boolean; lastScan: string };
type Scan = { id: string; segmentId: string; label: string; started: string; startedAt: string; duration: string; hosts: number; ports: number; status: "success" | "running" | "failed" };
type ScriptResult = { id: string; output: string };
type InventoryRow = {
  id: string;
  segmentId: string;
  ip: string;
  hostname: string;
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  banner: string;
  scripts: ScriptResult[];
};
type HostChange = {
  ip: string;
  hostname: string;
  severity: "high" | "medium" | "low";
  changes: { kind: "added" | "removed" | "changed"; port: string; title: string; before?: string; after?: string }[];
};
type SettingsData = { speed: string; exclusions: string; flags: string; scripts: string; schedule_enabled: boolean; day: string; time: string };
type DashboardData = { scans: number; hosts: number; average_duration: number; latest: { started_at?: string; status?: string } | null; settings: SettingsData };
type HealthData = { status: string; nmap: string; database_bytes: number; scan_files_bytes: number; scheduler: string };

function apiUrl(path: string) {
  if (typeof window === "undefined") return `http://localhost:8000${path}`;
  return `${window.location.protocol}//${window.location.hostname}:8000${path}`;
}

function formatDuration(seconds?: number) {
  if (!seconds) return "—";
  const minutes = Math.floor(seconds / 60);
  return `${minutes}м ${Math.round(seconds % 60)}с`;
}

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} МБ`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} ГБ`;
}

const scheduleDays: Record<string, string> = {
  monday: "Понедельник",
  tuesday: "Вторник",
  wednesday: "Среда",
  thursday: "Четверг",
  friday: "Пятница",
  saturday: "Суббота",
  sunday: "Воскресенье",
  daily: "Каждый день",
};

const navItems: { id: View; label: string; hint: string; icon: typeof BarChart3 }[] = [
  { id: "dashboard", label: "Обзор", hint: "Состояние сервиса", icon: BarChart3 },
  { id: "changes", label: "Изменения", hint: "Сравнение сканов", icon: History },
  { id: "search", label: "Поиск", hint: "Инвентаризация", icon: Search },
  { id: "manual", label: "Ручной анализ", hint: "Nmap XML", icon: FileSearch },
  { id: "settings", label: "Настройки", hint: "Сегменты и запуск", icon: Settings },
];

const pageMeta: Record<View, { title: string; subtitle: string }> = {
  dashboard: { title: "Обзор сети", subtitle: "Сводка по сканированию и ближайшим заданиям" },
  changes: { title: "Изменения", subtitle: "Сравнение состояния узлов между снимками" },
  search: { title: "Поиск по активам", subtitle: "Порты, сервисы, технологии, баннеры и NSE" },
  manual: { title: "Ручной анализ", subtitle: "Локальный разбор XML-отчёта Nmap" },
  settings: { title: "Настройки", subtitle: "Область сканирования, расписание и параметры Nmap" },
};

function StatusPill({ tone, children }: { tone: "ok" | "warn" | "danger" | "muted" | "info"; children: ReactNode }) {
  return <span className={`status-pill ${tone}`}><i />{children}</span>;
}

function IconButton({ label, children, onClick, className = "" }: { label: string; children: ReactNode; onClick?: () => void; className?: string }) {
  return <button className={`icon-button ${className}`} aria-label={label} title={label} onClick={onClick}>{children}</button>;
}

function Panel({ title, meta, action, children, className = "" }: { title: string; meta?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-header"><div><h2>{title}</h2>{meta && <p>{meta}</p>}</div>{action}</div>{children}</section>;
}

function Dashboard({ onNavigate, onRunScan, data, health, recentScans, segments }: { onNavigate: (view: View) => void; onRunScan: () => void; data: DashboardData | null; health: HealthData | null; recentScans: Scan[]; segments: Segment[] }) {
  const activity = useMemo(() => {
    const days = Array.from({ length: 14 }, (_, offset) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (13 - offset));
      return { key: date.toISOString().slice(0, 10), label: date.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" }), success: 0, failed: 0 };
    });
    for (const scan of recentScans) {
      const item = days.find(day => day.key === scan.startedAt.slice(0, 10));
      if (item && scan.status === "success") item.success += 1;
      if (item && scan.status === "failed") item.failed += 1;
    }
    return days;
  }, [recentScans]);
  const activitySuccess = activity.reduce((total, day) => total + day.success, 0);
  const activityFailed = activity.reduce((total, day) => total + day.failed, 0);
  const maxActivity = Math.max(1, ...activity.map(day => day.success + day.failed));
  const settings = data?.settings;
  const enabledSegments = segments.filter(segment => segment.enabled && segment.id !== "manual");
  const nextRun = settings?.schedule_enabled ? `${scheduleDays[settings.day] || settings.day}, ${settings.time}` : "Отключено";
  return <div className="view-stack">
    <div className="stat-grid">
      <button className="stat-card" onClick={() => onNavigate("changes")}>
        <div className="stat-top"><span>Всего сканов</span><History size={17} /></div>
        <strong>{data ? data.scans.toLocaleString("ru-RU") : "—"}</strong><small>успешных снимков в хранилище</small>
      </button>
      <button className="stat-card" onClick={() => onNavigate("search")}>
        <div className="stat-top"><span>Активных узлов</span><Server size={17} /></div>
        <strong>{data ? data.hosts.toLocaleString("ru-RU") : "—"}</strong><small>уникальных адресов в снимках</small>
      </button>
      <div className="stat-card">
        <div className="stat-top"><span>Среднее время</span><Clock3 size={17} /></div>
        <strong>{data ? formatDuration(data.average_duration) : "—"}</strong><small>по завершённым заданиям</small>
      </div>
      <button className="stat-card" onClick={onRunScan}>
        <div className="stat-top"><span>Следующий запуск</span><CalendarClock size={17} /></div>
        <strong className="compact-value">{nextRun}</strong><small>{enabledSegments.length} активных сегментов</small>
      </button>
    </div>

    <div className="dashboard-grid">
      <Panel title="Активность сканирования" meta="Последние 14 дней" className="activity-panel" action={<button className="text-button" onClick={() => onNavigate("changes")}>История <ArrowRight size={14} /></button>}>
        <div className="activity-summary"><div><strong>{activitySuccess + activityFailed}</strong><span>завершённых заданий</span></div><div className="legend"><span><i className="legend-dot success" />Успешно {activitySuccess}</span><span><i className="legend-dot failed" />Ошибки {activityFailed}</span></div></div>
        <div className="bar-chart" aria-label="График активности за 14 дней">
          {activity.map((day, index) => { const total = day.success + day.failed; return <div className="bar-column" key={day.key} title={`${day.label}: ${total}`}><div className="bar-track"><div className={`bar-fill ${day.failed ? "has-failure" : ""} ${total === 0 ? "empty" : ""}`} style={{ height: total ? `${Math.max(8, total / maxActivity * 78)}px` : "0" }} /></div><span>{index % 2 === 0 ? day.label : ""}</span></div>; })}
        </div>
      </Panel>

      <Panel title="Состояние сервиса" meta={health ? "Данные получены от API" : "Ожидание ответа API"}>
        <div className="health-list">
          <div className="health-row"><span className={`health-icon ${health ? "good" : ""}`}><Network size={17} /></span><div><strong>Nmap runner</strong><small>{health?.nmap || "нет соединения"}</small></div><StatusPill tone={health ? "ok" : "danger"}>{health ? "Работает" : "Недоступен"}</StatusPill></div>
          <div className="health-row"><span className={`health-icon ${health?.scheduler === "running" ? "good" : ""}`}><CircleDot size={17} /></span><div><strong>Планировщик</strong><small>{settings?.schedule_enabled ? `${enabledSegments.length} сегментов по расписанию` : "расписание отключено"}</small></div><StatusPill tone={health?.scheduler === "running" ? "ok" : "danger"}>{health?.scheduler === "running" ? "Работает" : "Недоступен"}</StatusPill></div>
          <div className="health-row"><span className={`health-icon ${health ? "good" : ""}`}><Gauge size={17} /></span><div><strong>Хранилище</strong><small>SQLite и XML-снимки</small></div><span className="health-value">{health ? formatBytes(health.database_bytes + health.scan_files_bytes) : "—"}</span></div>
        </div>
        <button className="full-width-button" onClick={() => onNavigate("settings")}><Settings size={15} />Настройки сервиса</button>
      </Panel>
    </div>

    <div className="dashboard-grid lower">
      <Panel title="Последние сканы" meta="Все сегменты" action={<button className="text-button" onClick={() => onNavigate("changes")}>Смотреть все <ArrowRight size={14} /></button>}>
        <div className="table-wrap"><table className="data-table compact"><thead><tr><th>Сегмент</th><th>Начало</th><th>Время</th><th>Узлы</th><th>Статус</th></tr></thead><tbody>
          {recentScans.slice(0, 4).map(scan => <tr key={scan.id}><td><div className="cell-primary"><span className="segment-mark" />{segments.find(s => s.id === scan.segmentId)?.name || scan.segmentId}</div></td><td>{scan.started}</td><td>{scan.duration}</td><td>{scan.hosts}</td><td><StatusPill tone={scan.status === "success" ? "ok" : scan.status === "running" ? "info" : "danger"}>{scan.status === "success" ? "Готово" : scan.status === "running" ? "В работе" : "Ошибка"}</StatusPill></td></tr>)}
          {!recentScans.length && <tr><td colSpan={5}><div className="empty-table"><History size={20} /><strong>Сканов пока нет</strong><span>Запустите первый скан сегмента</span></div></td></tr>}
        </tbody></table></div>
      </Panel>
      <Panel title="Ближайшие задания" meta="Europe/Moscow">
        <div className="schedule-list">
          {settings?.schedule_enabled && enabledSegments.map(segment => <div className="schedule-row" key={segment.id}><div className="date-box"><CalendarClock size={15} /><span>ПЛАН</span></div><div><strong>{segment.name}</strong><small>{scheduleDays[settings.day] || settings.day} · {settings.time}</small></div><span className="schedule-flags">-{settings.speed} {settings.flags}</span></div>)}
          {(!settings?.schedule_enabled || !enabledSegments.length) && <div className="empty-table"><CalendarClock size={20} /><strong>Нет активных заданий</strong><span>Добавьте сегмент и включите расписание в настройках</span></div>}
        </div>
      </Panel>
    </div>
  </div>;
}

function ChangesView({ segmentId, setSegmentId, segments }: { segmentId: string; setSegmentId: (value: string) => void; segments: Segment[] }) {
  const [availableScans, setAvailableScans] = useState<Scan[]>([]);
  const segmentScans = availableScans.filter(scan => scan.segmentId === segmentId);
  const [fromScan, setFromScan] = useState("");
  const [toScan, setToScan] = useState("");
  const [expanded, setExpanded] = useState<string[]>([]);
  const [severity, setSeverity] = useState("all");
  const [changeData, setChangeData] = useState<HostChange[]>([]);
  const visibleChanges = changeData.filter(host => severity === "all" || host.severity === severity);

  useEffect(() => {
    if (!segmentId) return;
    fetch(apiUrl(`/api/scans?segment_id=${encodeURIComponent(segmentId)}`)).then(response => response.ok ? response.json() : Promise.reject()).then((items: Array<Record<string, unknown>>) => {
      if (!items.length) { setAvailableScans([]); setFromScan(""); setToScan(""); setChangeData([]); return; }
      const mapped: Scan[] = items.map(item => ({ id: String(item.id), segmentId: String(item.segment_id), label: new Date(String(item.started_at)).toLocaleString("ru-RU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }), started: new Date(String(item.started_at)).toLocaleString("ru-RU"), startedAt: String(item.started_at), duration: formatDuration(Number(item.duration_seconds)), hosts: Number(item.hosts), ports: Number(item.ports), status: item.status as Scan["status"] }));
      setAvailableScans(current => [...current.filter(scan => scan.segmentId !== segmentId), ...mapped]);
      setToScan(mapped[0]?.id || ""); setFromScan(mapped[1]?.id || "");
    }).catch(() => undefined);
  }, [segmentId]);

  useEffect(() => {
    if (!fromScan || !toScan) return;
    fetch(apiUrl(`/api/changes?segment_id=${encodeURIComponent(segmentId)}&older=${encodeURIComponent(fromScan)}&newer=${encodeURIComponent(toScan)}`)).then(response => response.ok ? response.json() : Promise.reject()).then((payload: { hosts: HostChange[] }) => setChangeData(payload.hosts)).catch(() => undefined);
  }, [segmentId, fromScan, toScan]);

  function updateSegment(value: string) {
    setSegmentId(value);
    const next = availableScans.filter(scan => scan.segmentId === value);
    setToScan(next[0]?.id ?? "");
    setFromScan(next[1]?.id ?? "");
  }

  function toggle(ip: string) { setExpanded(current => current.includes(ip) ? current.filter(item => item !== ip) : [...current, ip]); }
  async function exportPdf() {
    if (!fromScan || !toScan) { window.print(); return; }
    try {
      const response = await fetch(apiUrl(`/api/reports/changes.pdf?segment_id=${encodeURIComponent(segmentId)}&older=${encodeURIComponent(fromScan)}&newer=${encodeURIComponent(toScan)}`));
      if (!response.ok) throw new Error();
      const href = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = href; link.download = `vizor-${segmentId}-changes.pdf`; link.click(); URL.revokeObjectURL(href);
    } catch { window.print(); }
  }

  return <div className="view-stack">
    <section className="filter-bar compare-bar">
      <label><span>Сегмент сети</span><select value={segmentId} onChange={event => updateSegment(event.target.value)}><option value="">Выберите сегмент</option>{segments.filter(segment => segment.id !== "manual").map(segment => <option value={segment.id} key={segment.id}>{segment.name}</option>)}</select></label>
      <label><span>Предыдущий снимок</span><select value={fromScan} onChange={event => setFromScan(event.target.value)}>{segmentScans.slice(1).map(scan => <option value={scan.id} key={scan.id}>{scan.label}</option>)}</select></label>
      <div className="compare-arrow"><ArrowRight size={16} /></div>
      <label><span>Новый снимок</span><select value={toScan} onChange={event => setToScan(event.target.value)}>{segmentScans.map(scan => <option value={scan.id} key={scan.id}>{scan.label}</option>)}</select></label>
      <button className="secondary-button export-button" onClick={exportPdf}><Download size={15} />Экспорт PDF</button>
    </section>

    <div className="compare-summary">
      <div><span>Изменённых узлов</span><strong>{changeData.length}</strong></div><div><span>Новых портов</span><strong className="danger-text">{changeData.flatMap(host => host.changes).filter(change => change.kind === "added").length}</strong></div><div><span>Закрытых портов</span><strong>{changeData.flatMap(host => host.changes).filter(change => change.kind === "removed").length}</strong></div><div><span>Изменений сервисов</span><strong className="warning-text">{changeData.flatMap(host => host.changes).filter(change => change.kind === "changed").length}</strong></div>
      <div className="compare-note"><Check size={16} /><span>Сравнение выполнено<strong>{segmentScans[0]?.hosts || 0} узлов · {segmentScans[0]?.ports || 0} портов</strong></span></div>
    </div>

    <div className="list-toolbar"><div><strong>Изменения по узлам</strong><span>{visibleChanges.length} из {changeData.length}</span></div><div className="chip-group"><button className={severity === "all" ? "active" : ""} onClick={() => setSeverity("all")}>Все</button><button className={severity === "high" ? "active" : ""} onClick={() => setSeverity("high")}>Критичные</button><button className={severity === "medium" ? "active" : ""} onClick={() => setSeverity("medium")}>Важные</button></div></div>
    <div className="change-list">
      {visibleChanges.map(host => <article className={`change-host ${expanded.includes(host.ip) ? "expanded" : ""}`} key={host.ip}>
        <button className="change-host-header" onClick={() => toggle(host.ip)}><span className={`severity-indicator ${host.severity}`} />{expanded.includes(host.ip) ? <ChevronDown size={17} /> : <ChevronRight size={17} />}<span className="host-icon"><Server size={16} /></span><span className="host-identity"><strong>{host.hostname}</strong><small>{host.ip}</small></span><span className="change-count">{host.changes.length} {host.changes.length === 1 ? "изменение" : "изменения"}</span><span className={`severity-label ${host.severity}`}>{host.severity === "high" ? "Критично" : host.severity === "medium" ? "Важно" : "Информация"}</span></button>
        {expanded.includes(host.ip) && <div className="change-details">{host.changes.map((change, index) => <div className="change-row" key={`${change.port}-${index}`}><span className={`change-kind ${change.kind}`}>{change.kind === "added" ? <Plus size={14} /> : change.kind === "removed" ? <X size={14} /> : <RefreshCw size={14} />}</span><span className="port-code">{change.port}</span><div><strong>{change.title}</strong><div className="change-values">{change.before && <span className="before">{change.before}</span>}{change.before && change.after && <ArrowRight size={13} />}{change.after && <span className="after">{change.after}</span>}</div></div></div>)}</div>}
      </article>)}
      {!visibleChanges.length && <div className="panel empty-table"><Check size={22} /><strong>Изменений не найдено</strong><span>Выбранные снимки совпадают по наблюдаемым параметрам</span></div>}
    </div>
  </div>;
}

function SearchWorkbench({ rows, segmentId, setSegmentId, segments = [], manual = false }: { rows: InventoryRow[]; segmentId: string; setSegmentId: (value: string) => void; segments?: Segment[]; manual?: boolean }) {
  const [query, setQuery] = useState("");
  const [port, setPort] = useState("");
  const [service, setService] = useState("");
  const [script, setScript] = useState("");
  const [openRow, setOpenRow] = useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(true);
  const filtered = useMemo(() => rows.filter(row => {
    if (!manual && segmentId !== "all" && row.segmentId !== segmentId) return false;
    const haystack = [row.ip, row.hostname, row.service, row.product, row.version, row.banner, ...row.scripts.flatMap(item => [item.id, item.output])].join(" ").toLowerCase();
    return (!query || haystack.includes(query.toLowerCase())) && (!port || String(row.port) === port) && (!service || [row.service, row.product].join(" ").toLowerCase().includes(service.toLowerCase())) && (!script || row.scripts.some(item => `${item.id} ${item.output}`.toLowerCase().includes(script.toLowerCase())));
  }), [rows, manual, segmentId, query, port, service, script]);
  const hasFilters = Boolean(query || port || service || script || (!manual && segmentId !== "all"));
  function reset() { setQuery(""); setPort(""); setService(""); setScript(""); if (!manual) setSegmentId("all"); }

  return <div className="view-stack">
    <section className="search-shell">
      <div className="primary-search"><Search size={18} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="IP, имя узла, сервис, технология или баннер…" /><kbd>Enter</kbd><button onClick={() => setFiltersOpen(!filtersOpen)} className={filtersOpen ? "active" : ""}><SlidersHorizontal size={16} />Фильтры</button></div>
      {filtersOpen && <div className="advanced-filters">
        {!manual && <label><span>Сегмент</span><select value={segmentId} onChange={event => setSegmentId(event.target.value)}><option value="all">Все сегменты</option>{segments.filter(item => item.id !== "manual").map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label>}
        <label><span>Порт</span><input inputMode="numeric" placeholder="443" value={port} onChange={event => setPort(event.target.value.replace(/\D/g, ""))} /></label>
        <label><span>Сервис / продукт</span><input placeholder="nginx, smb, ssh…" value={service} onChange={event => setService(event.target.value)} /></label>
        <label className="script-filter"><span>NSE-скрипт или результат</span><input placeholder="ssl-cert, signing, CVE…" value={script} onChange={event => setScript(event.target.value)} /></label>
        <button className="reset-button" disabled={!hasFilters} onClick={reset}><RotateCcw size={14} />Сбросить</button>
      </div>}
    </section>
    <div className="results-head"><div><strong>{filtered.length}</strong><span>совпадений</span>{manual && <StatusPill tone="info">XML-источник</StatusPill>}</div><span>Поиск по последним успешным снимкам</span></div>
    <Panel title="Результаты" meta={`${filtered.length} записей`} className="results-panel">
      <div className="table-wrap"><table className="data-table results-table"><thead><tr><th>Узел</th><th>Порт</th><th>Сервис</th><th>Технология</th><th>Версия</th><th>NSE</th><th /></tr></thead><tbody>
        {filtered.map(row => <Fragment key={row.id}><tr className={openRow === row.id ? "selected" : ""} onClick={() => setOpenRow(openRow === row.id ? null : row.id)}><td><div className="host-cell"><span className="online-dot" /><div><strong>{row.ip}</strong><small>{row.hostname || "—"}</small></div></div></td><td><span className="port-badge">{row.port}/{row.protocol}</span></td><td><strong className="service-name">{row.service || "unknown"}</strong></td><td>{row.product || "—"}</td><td><span className="mono-muted">{row.version || "—"}</span></td><td>{row.scripts.length ? <span className="nse-count"><Code2 size={13} />{row.scripts.length}</span> : "—"}</td><td>{openRow === row.id ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</td></tr>
        {openRow === row.id && <tr className="detail-table-row"><td colSpan={7}><div className="result-detail"><div><span>Баннер</span><code>{row.banner || "Данные не получены"}</code></div><div className="script-results"><span>Результаты NSE</span>{row.scripts.length ? row.scripts.map(item => <div className="script-output" key={item.id}><strong>{item.id}</strong><pre>{item.output}</pre></div>) : <code>Скрипты не выполнялись</code>}</div></div></td></tr>}</Fragment>)}
        {!filtered.length && <tr><td colSpan={7}><div className="empty-table"><Search size={22} /><strong>Совпадений не найдено</strong><span>Измените условия поиска или сбросьте фильтры</span></div></td></tr>}
      </tbody></table></div>
    </Panel>
  </div>;
}

function parseNmapXml(text: string): InventoryRow[] {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.querySelector("parsererror") || !doc.querySelector("nmaprun")) throw new Error("Файл не похож на XML-отчёт Nmap");
  const rows: InventoryRow[] = [];
  doc.querySelectorAll("host").forEach((host, hostIndex) => {
    const ip = host.querySelector('address[addrtype="ipv4"]')?.getAttribute("addr") || host.querySelector("address")?.getAttribute("addr") || "unknown";
    const hostname = host.querySelector("hostname")?.getAttribute("name") || "";
    const hostScripts = Array.from(host.querySelectorAll(":scope > hostscript > script")).map(scriptNode => ({ id: scriptNode.getAttribute("id") || "script", output: scriptNode.getAttribute("output") || scriptNode.textContent?.trim() || "" }));
    host.querySelectorAll("port").forEach((portNode, portIndex) => {
      const serviceNode = portNode.querySelector(":scope > service");
      const scripts = Array.from(portNode.querySelectorAll(":scope > script")).map(scriptNode => ({ id: scriptNode.getAttribute("id") || "script", output: scriptNode.getAttribute("output") || scriptNode.textContent?.trim() || "" }));
      rows.push({ id: `xml-${hostIndex}-${portIndex}`, segmentId: "manual", ip, hostname, port: Number(portNode.getAttribute("portid") || 0), protocol: portNode.getAttribute("protocol") || "tcp", state: portNode.querySelector("state")?.getAttribute("state") || "unknown", service: serviceNode?.getAttribute("name") || "unknown", product: serviceNode?.getAttribute("product") || "", version: serviceNode?.getAttribute("version") || "", banner: [serviceNode?.getAttribute("product"), serviceNode?.getAttribute("version"), serviceNode?.getAttribute("extrainfo")].filter(Boolean).join(" "), scripts: [...scripts, ...hostScripts] });
    });
  });
  return rows;
}

function ManualView() {
  const [rows, setRows] = useState<InventoryRow[]>([]);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  async function loadFile(file?: File) {
    if (!file) return;
    try { const text = await file.text(); const parsed = parseNmapXml(text); setRows(parsed); setFileName(file.name); setError(""); }
    catch (reason) { setRows([]); setFileName(""); setError(reason instanceof Error ? reason.message : "Не удалось прочитать файл"); }
  }
  function onDrop(event: DragEvent<HTMLDivElement>) { event.preventDefault(); setDragging(false); loadFile(event.dataTransfer.files[0]); }
  if (!rows.length) return <div className="manual-empty"><div className="manual-card"><div className="upload-icon"><Upload size={24} /></div><h2>Загрузите отчёт Nmap</h2><p>Файл обрабатывается локально в браузере. Поддерживается стандартный XML, включая результаты NSE-скриптов.</p><div className={`drop-zone ${dragging ? "dragging" : ""}`} onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()}><FileSearch size={22} /><strong>Перетащите XML сюда</strong><span>или нажмите, чтобы выбрать файл · до 100 МБ</span><input ref={inputRef} type="file" accept=".xml,text/xml,application/xml" onChange={(event: ChangeEvent<HTMLInputElement>) => loadFile(event.target.files?.[0])} /></div>{error && <div className="inline-alert"><AlertTriangle size={15} />{error}</div>}<div className="xml-hint"><TerminalSquare size={15} /><code>nmap -sV -sC -oX scan.xml 10.20.0.0/24</code></div></div></div>;
  return <div className="view-stack"><div className="source-banner"><div><FileSearch size={18} /><span><strong>{fileName}</strong>{rows.length} открытых портов · {new Set(rows.map(row => row.ip)).size} узлов</span></div><button className="secondary-button" onClick={() => { setRows([]); setFileName(""); }}><Upload size={15} />Другой файл</button></div><SearchWorkbench rows={rows} segmentId="manual" setSegmentId={() => undefined} manual /></div>;
}

function SettingsView({ segments, setSegments, settings, onSaved, showToast }: { segments: Segment[]; setSegments: (segments: Segment[]) => void; settings: SettingsData; onSaved: () => Promise<void>; showToast: (message: string) => void }) {
  const [speed, setSpeed] = useState(settings.speed);
  const [exclusions, setExclusions] = useState(settings.exclusions);
  const [flags, setFlags] = useState(settings.flags);
  const [scripts, setScripts] = useState(settings.scripts);
  const [day, setDay] = useState(settings.day);
  const [time, setTime] = useState(settings.time);
  const [scheduleEnabled, setScheduleEnabled] = useState(settings.schedule_enabled);
  const [editing, setEditing] = useState<string | null>(null);
  const [validation, setValidation] = useState<"idle" | "valid" | "invalid">("idle");
  const [saving, setSaving] = useState(false);
  const payload = { segments, speed, exclusions, flags, scripts, day, time, schedule_enabled: scheduleEnabled };
  async function save() {
    setSaving(true);
    try {
      const response = await fetch(apiUrl("/api/settings"), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || "Сервер отклонил настройки");
      setValidation("valid");
      await onSaved();
      showToast("Настройки сохранены");
    } catch (reason) {
      setValidation("invalid");
      showToast(reason instanceof Error ? reason.message : "Не удалось сохранить настройки");
    } finally { setSaving(false); }
  }
  async function validate() {
    try {
      const response = await fetch(apiUrl("/api/settings/validate"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || "Конфигурация некорректна");
      setValidation("valid"); showToast("Конфигурация Nmap корректна");
    } catch (reason) { setValidation("invalid"); showToast(reason instanceof Error ? reason.message : "Ошибка проверки конфигурации"); }
  }
  function addSegment() { const next = { id: `segment-${Date.now()}`, name: "Новый сегмент", cidrs: "", enabled: true, lastScan: "ещё не запускался" }; setSegments([...segments, next]); setEditing(next.id); }
  return <div className="settings-layout">
    <div className="settings-main">
      <Panel title="Сегменты сети" meta="Цели для автоматического сканирования" action={<button className="secondary-button" onClick={addSegment}><Plus size={15} />Добавить сегмент</button>}>
        <div className="segment-settings-list">{segments.map(segment => <div className="segment-setting" key={segment.id}><button className={`toggle ${segment.enabled ? "on" : ""}`} aria-label={`${segment.enabled ? "Выключить" : "Включить"} ${segment.name}`} onClick={() => setSegments(segments.map(item => item.id === segment.id ? { ...item, enabled: !item.enabled } : item))}><span /></button><div className="segment-fields">{editing === segment.id ? <><input value={segment.name} onChange={event => setSegments(segments.map(item => item.id === segment.id ? { ...item, name: event.target.value } : item))} /><input className="mono-input" placeholder="10.20.0.0/24" value={segment.cidrs} onChange={event => setSegments(segments.map(item => item.id === segment.id ? { ...item, cidrs: event.target.value } : item))} /></> : <><strong>{segment.name}</strong><code>{segment.cidrs}</code></>}</div><div className="segment-last"><span>Последний скан</span><strong>{segment.lastScan}</strong></div><button className="text-button" onClick={() => setEditing(editing === segment.id ? null : segment.id)}>{editing === segment.id ? "Готово" : "Изменить"}</button></div>)}{!segments.length && <div className="empty-table"><Network size={20} /><strong>Сегменты не настроены</strong><span>Добавьте первую разрешённую область сканирования</span></div>}</div>
      </Panel>

      <Panel title="Параметры Nmap" meta="Применяются ко всем заданиям">
        <div className="settings-form">
          <div className="form-row"><div><label>Скорость сканирования</label><p>Timing template Nmap. T3 — безопасное значение для внутренней сети.</p></div><div className="speed-selector">{["T1", "T2", "T3", "T4", "T5"].map(item => <button className={speed === item ? "active" : ""} onClick={() => setSpeed(item)} key={item}>{item}</button>)}</div></div>
          <div className="form-row"><div><label htmlFor="exclusions">Исключения</label><p>IP-адреса и диапазоны через запятую.</p></div><input id="exclusions" className="settings-input mono-input" value={exclusions} onChange={event => setExclusions(event.target.value)} /></div>
          <div className="form-row"><div><label htmlFor="flags">Разрешённые флаги</label><p>Используется строгий allowlist. Например: -sS -sV -O -Pn -p 22,80,443 --reason.</p></div><input id="flags" className="settings-input mono-input" value={flags} onChange={event => setFlags(event.target.value)} /></div>
          <div className="form-row"><div><label htmlFor="scripts">NSE-скрипты</label><p>Категории или имена скриптов через запятую.</p></div><input id="scripts" className="settings-input mono-input" value={scripts} onChange={event => setScripts(event.target.value)} /></div>
          <div className="command-preview"><TerminalSquare size={16} /><code>nmap -{speed} {flags || ""} {scripts ? `--script ${scripts}` : ""} {exclusions ? `--exclude ${exclusions}` : ""} -oX &lt;scan.xml&gt; &lt;targets&gt;</code></div>
        </div>
      </Panel>

      <Panel title="Расписание" meta="Europe/Moscow (UTC+3)">
        <div className="schedule-settings"><div className="schedule-enabled"><span className="health-icon good"><CalendarClock size={17} /></span><div><strong>Автоматическое сканирование</strong><small>{scheduleEnabled ? `${scheduleDays[day] || day} · ${time}` : "Расписание приостановлено"}</small></div><button className={`toggle ${scheduleEnabled ? "on" : ""}`} aria-label={scheduleEnabled ? "Выключить расписание" : "Включить расписание"} onClick={() => setScheduleEnabled(!scheduleEnabled)}><span /></button></div><div className="schedule-controls"><label><span>День недели</span><select value={day} onChange={event => setDay(event.target.value)} disabled={!scheduleEnabled}><option value="monday">Каждый понедельник</option><option value="tuesday">Каждый вторник</option><option value="wednesday">Каждую среду</option><option value="thursday">Каждый четверг</option><option value="friday">Каждую пятницу</option><option value="saturday">Каждую субботу</option><option value="sunday">Каждое воскресенье</option><option value="daily">Каждый день</option></select></label><label><span>Время запуска</span><input type="time" value={time} onChange={event => setTime(event.target.value)} disabled={!scheduleEnabled} /></label></div></div>
      </Panel>
    </div>
    <aside className="settings-aside"><div className="sticky-actions"><h3>Применить изменения</h3><p>Новые параметры будут использованы при следующем запуске. Активные сканы не прерываются.</p><button className="primary-button full" onClick={save} disabled={saving}><Check size={16} />{saving ? "Сохраняем…" : "Сохранить настройки"}</button><button className="secondary-button full" onClick={validate}><Zap size={15} />Проверить конфигурацию</button>{validation !== "idle" && <div className={`config-status ${validation === "invalid" ? "invalid" : ""}`}><ShieldCheck size={17} /><div><strong>{validation === "valid" ? "Конфигурация валидна" : "Найдена ошибка"}</strong><span>{validation === "valid" ? "Проверено API Vizor" : "Исправьте параметры и повторите проверку"}</span></div></div>}</div></aside>
  </div>;
}

export default function VizorApp() {
  const [view, setView] = useState<View>("dashboard");
  const [mobileNav, setMobileNav] = useState(false);
  const [segmentId, setSegmentId] = useState("");
  const [searchSegment, setSearchSegment] = useState("all");
  const [segments, setSegments] = useState<Segment[]>([]);
  const [inventoryRows, setInventoryRows] = useState<InventoryRow[]>([]);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [settingsData, setSettingsData] = useState<SettingsData | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [apiError, setApiError] = useState(false);
  const [lastSync, setLastSync] = useState("");
  const [toast, setToast] = useState("");
  const [scanning, setScanning] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const meta = pageMeta[view];
  const loadBackend = useCallback(async () => {
    try {
      const [segmentResponse, dashboardResponse, searchResponse, scansResponse, healthResponse] = await Promise.all([
        fetch(apiUrl("/api/segments")),
        fetch(apiUrl("/api/dashboard")),
        fetch(apiUrl("/api/search?limit=5000")),
        fetch(apiUrl("/api/scans?limit=20")),
        fetch(apiUrl("/api/health")),
      ]);
      if (!segmentResponse.ok || !dashboardResponse.ok || !searchResponse.ok || !scansResponse.ok || !healthResponse.ok) throw new Error("API unavailable");
      const [segmentItems, dashboardItem, searchItems, scanItems, healthItem] = await Promise.all([segmentResponse.json(), dashboardResponse.json(), searchResponse.json(), scansResponse.json(), healthResponse.json()]);
      setSegments(segmentItems as Segment[]);
      setDashboardData(dashboardItem as DashboardData);
      setSettingsData((dashboardItem as DashboardData).settings);
      setHealth(healthItem as HealthData);
      setApiError(false);
      setLastSync(new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
      setSegmentId(current => current || (segmentItems as Segment[]).find(item => item.enabled && item.id !== "manual")?.id || "");
      setInventoryRows((searchItems as Array<Record<string, unknown>>).map((item, index) => ({ id: `api-${index}-${item.ip}-${item.port}`, segmentId: String(item.segment_id), ip: String(item.ip), hostname: String(item.hostname || ""), port: Number(item.port), protocol: String(item.protocol), state: String(item.state), service: String(item.service || "unknown"), product: String(item.product || ""), version: String(item.version || ""), banner: String(item.banner || ""), scripts: item.scripts as ScriptResult[] || [] })));
      setRecentScans((scanItems as Array<Record<string, unknown>>).map(item => ({ id: String(item.id), segmentId: String(item.segment_id), label: new Date(String(item.started_at)).toLocaleString("ru-RU"), started: new Date(String(item.started_at)).toLocaleString("ru-RU"), startedAt: String(item.started_at), duration: item.duration_seconds ? formatDuration(Number(item.duration_seconds)) : "—", hosts: Number(item.hosts || 0), ports: Number(item.ports || 0), status: item.status as Scan["status"] })));
    } catch {
      setApiError(true); setDashboardData(null); setHealth(null); setSettingsData(null); setSegments([]); setInventoryRows([]); setRecentScans([]);
    }
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => { loadBackend(); }, 0);
    return () => window.clearTimeout(timer);
  }, [loadBackend]);
  function showToast(message: string) { setToast(message); window.setTimeout(() => setToast(""), 2800); }
  async function runScan() {
    if (scanning || !segmentId) { if (!segmentId) showToast("Сначала добавьте активный сегмент в настройках"); return; }
    setScanning(true); showToast("Сканирование поставлено в очередь");
    try {
      const response = await fetch(apiUrl("/api/scans/run"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ segment_id: segmentId }) });
      if (!response.ok) { const payload = await response.json().catch(() => ({})); showToast(payload.detail || "Не удалось запустить скан"); }
      else { showToast("Nmap запущен в фоне"); await loadBackend(); }
    } catch { showToast("API Vizor недоступен — скан не запущен"); setApiError(true); }
    window.setTimeout(() => setScanning(false), 1800);
  }
  async function refresh() { setRefreshing(true); await loadBackend(); window.setTimeout(() => { setRefreshing(false); showToast("Данные обновлены"); }, 500); }
  function navigate(next: View) { setView(next); setMobileNav(false); window.scrollTo({ top: 0, behavior: "smooth" }); }
  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? "open" : ""}`}>
      <div className="brand"><span className="brand-mark"><ShieldCheck size={21} /></span><span><strong>VIZOR</strong><small>NETWORK MONITOR</small></span></div>
      <nav aria-label="Основная навигация">{navItems.map(item => { const Icon = item.icon; return <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => navigate(item.id)}><span className="nav-icon"><Icon size={18} /></span><span><strong>{item.label}</strong><small>{item.hint}</small></span>{view === item.id && <i />}</button>; })}</nav>
      <div className="sidebar-footer"><div className="runner-status"><span className={health ? "pulse-dot" : "offline-dot"} /><span><strong>Nmap runner</strong><small>{health ? "Готов к запуску" : "Нет соединения"}</small></span></div><div className="version">Vizor 0.1.0 <span>•</span> {health?.nmap || "Nmap —"}</div></div>
    </aside>
    {mobileNav && <button className="sidebar-backdrop" aria-label="Закрыть меню" onClick={() => setMobileNav(false)} />}
    <main className="main-area">
      <header className="topbar"><div className="title-group"><IconButton label="Открыть меню" className="menu-button" onClick={() => setMobileNav(true)}><Menu size={19} /></IconButton><div><div className="breadcrumb"><span>Vizor</span><ChevronRight size={12} /><span>{meta.title}</span></div><h1>{meta.title}</h1><p>{meta.subtitle}</p></div></div><div className="top-actions"><div className="sync-time"><span className={apiError ? "offline-dot" : "online-dot"} /><span><strong>{apiError ? "Сервис недоступен" : "Сервис доступен"}</strong><small>{lastSync ? `Синхронизация ${lastSync}` : "Подключение…"}</small></span></div><IconButton label="Обновить данные" onClick={refresh}><RefreshCw size={17} className={refreshing ? "spinning" : ""} /></IconButton><button className="primary-button" onClick={runScan} disabled={scanning || !segmentId || apiError}>{scanning ? <RefreshCw size={16} className="spinning" /> : <Play size={16} fill="currentColor" />}{scanning ? "Запускаем…" : "Запустить скан"}</button></div></header>
      <div className="content-area">
        {apiError && <div className="offline-banner"><AlertTriangle size={17} /><div><strong>Нет соединения с API Vizor</strong><span>Данные не подменяются демонстрационными значениями. Проверьте контейнер и повторите подключение.</span></div><button className="secondary-button" onClick={refresh}>Повторить</button></div>}
        {view === "dashboard" && <Dashboard onNavigate={navigate} onRunScan={runScan} data={dashboardData} health={health} recentScans={recentScans} segments={segments} />}
        {view === "changes" && <ChangesView segmentId={segmentId} setSegmentId={setSegmentId} segments={segments} />}
        {view === "search" && <SearchWorkbench rows={inventoryRows} segmentId={searchSegment} setSegmentId={setSearchSegment} segments={segments} />}
        {view === "manual" && <ManualView />}
        {view === "settings" && settingsData && <SettingsView key={`${settingsData.speed}-${settingsData.time}-${segments.length}`} segments={segments} setSegments={setSegments} settings={settingsData} onSaved={loadBackend} showToast={showToast} />}
        {view === "settings" && !settingsData && !apiError && <div className="panel empty-table"><RefreshCw size={20} className="spinning" /><strong>Загружаем настройки</strong></div>}
      </div>
    </main>
    {toast && <div className="toast"><Check size={16} />{toast}</div>}
  </div>;
}
