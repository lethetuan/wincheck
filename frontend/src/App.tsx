import { useEffect, useRef, useState } from "react";
import { GetStatus, Scan, RunOption, Elevate } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import { main } from "../wailsjs/go/models";

/* ── Nhật ký kỹ thuật (chỉ trong ngăn kéo) ──────────────────────────────── */
const KIND_CLS: Record<number, string> = {
  0: "text-slate-300", 1: "text-slate-300", 2: "", 3: "text-brand-700 font-bold",
  4: "text-slate-400", 5: "text-slate-400", 6: "text-brand-600", 7: "text-emerald-700 font-semibold",
  8: "text-amber-700", 9: "text-red-700 font-bold", 10: "text-teal-700 font-semibold",
  11: "text-slate-500", 12: "text-brand-600", 13: "text-brand-700 font-bold", 14: "text-slate-800",
};
const KIND_PREFIX: Record<number, string> = {
  4: "$ ", 5: "[>] ", 6: "[i] ", 7: "[+] ", 8: "[!] ", 9: "[-] ", 10: "[K] ", 12: "[?] ", 13: "[*] ",
};
const SEP = "  " + "─".repeat(60);
const pad = (s: string, n: number) => (s.length >= n ? s : s + " ".repeat(n - s.length));

function LogRow({ l }: { l: main.Line }) {
  const cls = "whitespace-pre-wrap break-words " + (KIND_CLS[l.kind] ?? "text-slate-800");
  if (l.kind === 0 || l.kind === 1) return <div className={cls}>{SEP}</div>;
  if (l.kind === 2) return <div className="h-2" />;
  if (l.kind === 3) return <div className={cls}>{"  " + l.text}</div>;
  if (l.kind === 11) return <div className={cls}>{"      " + l.text}</div>;
  if (l.kind === 14) {
    if (!(l.label || "").trim()) return <div className={cls}>{"      " + (l.value || "")}</div>;
    return (
      <div className={cls}>
        <span className="text-slate-400">{"      " + pad(l.label, 26) + "  "}</span>{l.value || ""}
      </div>
    );
  }
  return <div className={cls}>{"  " + (KIND_PREFIX[l.kind] ?? "") + l.text}</div>;
}

/* ── Bảng màu theo phán quyết (không dùng tím) ──────────────────────────── */
const TONE = {
  clean: { ring: "ring-emerald-200", bar: "bg-emerald-600", text: "text-emerald-700", soft: "bg-emerald-50", chip: "bg-emerald-100 text-emerald-800 ring-emerald-200" },
  // Cảnh báo (nghi vấn) dùng màu ĐỎ để nổi bật cảnh báo mạnh.
  suspicious: { ring: "ring-red-200", bar: "bg-red-500", text: "text-red-600", soft: "bg-red-50", chip: "bg-red-100 text-red-700 ring-red-200" },
  critical: { ring: "ring-red-300", bar: "bg-red-600", text: "text-red-700", soft: "bg-red-50", chip: "bg-red-100 text-red-800 ring-red-200" },
} as const;
type Level = keyof typeof TONE;

function VerdictIcon({ level, className = "" }: { level: Level; className?: string }) {
  const d = level === "clean" ? "M14 25l6 6 14-14" : level === "suspicious" ? "M24 13v15M24 34v.5" : "M15 15l18 18M33 15L15 33";
  return (
    <svg viewBox="0 0 48 48" fill="none" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d={d} />
    </svg>
  );
}

/* ── Ô trạng thái trong bảng kiểm tra ───────────────────────────────────── */
function StatusBadge({ status, text }: { status: string; text: string }) {
  const map: Record<string, string> = {
    ok: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    detected: "bg-red-50 text-red-700 ring-red-200 font-bold",
    warn: "bg-amber-50 text-amber-700 ring-amber-200",
    skipped: "bg-slate-100 text-slate-500 ring-slate-200",
    info: "bg-brand-50 text-brand-700 ring-brand-200",
  };
  return (
    <span className={"inline-block whitespace-nowrap rounded px-2 py-0.5 text-[11px] font-semibold ring-1 " + (map[status] ?? map.info)}>
      {text}
    </span>
  );
}

/* Nút công cụ: tiêu đề rõ ràng + mô tả ngắn bên dưới cho dễ hiểu */
function ToolBtn({ title, desc, danger, disabled, onClick }: {
  title: string; desc?: string; danger?: boolean; disabled?: boolean; onClick: () => void;
}) {
  const c = danger
    ? "border-red-200 bg-red-50 hover:bg-red-100 text-red-700"
    : "border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700";
  return (
    <button disabled={disabled} onClick={onClick}
      className={"mb-2 block w-full rounded-lg border px-3.5 py-2.5 text-left disabled:opacity-50 disabled:hover:bg-inherit " + c}>
      <div className="text-[13px] font-semibold">{title}</div>
      {desc && <div className={"mt-0.5 text-[11px] " + (danger ? "text-red-600/70" : "text-slate-400")}>{desc}</div>}
    </button>
  );
}

type Adv = { dlv: boolean; autoRemove: boolean; restart: boolean };
type Dialog = { kind: "key" } | { kind: "confirm"; msg: string; run: () => void } | null;
type Drawer = "log" | "tools" | null;

export default function App() {
  const [S, setS] = useState<Record<string, string>>({});
  const [admin, setAdmin] = useState(false);
  const [ready, setReady] = useState(false);
  const [verdict, setVerdict] = useState<main.Verdict | null>(null);
  const [scanning, setScanning] = useState(false);
  const [lines, setLines] = useState<main.Line[]>([]);
  const [statusText, setStatusText] = useState("");
  const [drawer, setDrawer] = useState<Drawer>(null);
  const [tab, setTab] = useState<"audit" | "system" | "hardware">("audit");
  // Không còn tùy chọn nâng cao/khởi động lại: giữ mặc định tắt (không reset máy).
  const [adv] = useState<Adv>({ dlv: false, autoRemove: false, restart: false });
  const [dialog, setDialog] = useState<Dialog>(null);
  const [keyInput, setKeyInput] = useState("");

  const advRef = useRef(adv); advRef.current = adv;
  const busyRef = useRef(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    EventsOn("log", (l: main.Line) => {
      setLines((p) => [...p, l]);
      const t = ((l.kind === 14 ? l.value : l.text) || "").trim();
      if (t) setStatusText(t.length > 120 ? t.slice(0, 120) + "…" : t);
    });
    (async () => {
      const st = await GetStatus();
      setS(st.strings); setAdmin(st.admin); setReady(true);
      if (st.admin) doScan(); // chỉ quét khi đã có quyền Admin
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { logRef.current?.scrollTo(0, logRef.current.scrollHeight); }, [lines]);

  async function doScan() {
    if (busyRef.current) return;
    busyRef.current = true; setScanning(true); setLines([]); setVerdict(null);
    try { setVerdict(await Scan()); } finally { busyRef.current = false; setScanning(false); }
  }

  async function doRun(opt: number, extra: { key?: string; confirm?: boolean }) {
    setDialog(null);
    if (busyRef.current) return;
    const a = advRef.current;
    const o = new main.RunOpts({
      // Luôn hiển thị key đầy đủ (không còn tùy chọn che).
      showFullKey: true, dlv: a.dlv, autoRemove: a.autoRemove, restart: a.restart,
      confirm: !!extra.confirm, key: extra.key || "", n: 1,
    });
    busyRef.current = true; setScanning(true); setDrawer("log");
    try { await RunOption(opt, o); } finally { busyRef.current = false; setScanning(false); }
  }

  function runTool(opt: number) {
    if (busyRef.current) return;
    if (opt === 4) { setKeyInput(""); setDialog({ kind: "key" }); return; }
    if (opt === 5) { setDialog({ kind: "confirm", msg: "Bạn CHẮC CHẮN muốn gỡ key bản quyền? Windows sẽ trở thành CHƯA KÍCH HOẠT.", run: () => doRun(5, { confirm: true }) }); return; }
    if (opt === 8) { setDialog({ kind: "confirm", msg: "DỌN SẠCH CRACK\n\nWinCheck sẽ kết thúc tiến trình, dừng/xóa dịch vụ, xóa tác vụ định kỳ, gỡ hook IFEO, xóa cấu hình KMS, xóa tệp công cụ crack và GỠ key kích hoạt.\n\nSau khi chạy, Windows sẽ CHƯA KÍCH HOẠT và cần cài key bản quyền thật. Nên khởi động lại máy sau khi dọn.\n\nBạn CHẮC CHẮN muốn tiếp tục?", run: () => doRun(8, { confirm: true }) }); return; }
    if (opt === 9) { setDialog({ kind: "confirm", msg: S["O9_Confirm"] || "GỠ SẠCH KEY OFFICE LẬU\n\nWinCheck sẽ quét tất cả phiên bản Office (Office 2010 - 2024, Office 365), xóa máy chủ KMS lậu và gỡ bỏ toàn bộ key kích hoạt tồn đọng.\n\nSau khi gỡ, bạn có thể nhập key bản quyền chính hãng để kích hoạt lại Office.\n\nBạn CHẮC CHẮN muốn tiếp tục?", run: () => doRun(9, { confirm: true }) }); return; }
    doRun(opt, {});
  }


  const level: Level = (verdict?.level as Level) || "clean";
  const tone = TONE[level];
  const crit = (verdict?.indicators || []).filter((i) => i.severity === "critical");
  const warn = (verdict?.indicators || []).filter((i) => i.severity === "warn");
  const btn = "h-8 rounded-md border border-slate-300 bg-white px-3 text-[13px] text-slate-700 hover:bg-slate-50 disabled:opacity-50 disabled:hover:bg-white";

  /* ── Màn chặn: bắt buộc quyền Admin ─────────────────────────────────── */
  if (ready && !admin) {
    return (
      <div className="flex h-full items-center justify-center bg-slate-100 p-6">
        <div className="w-full max-w-lg rounded-xl bg-white p-8 text-center shadow-lg ring-1 ring-slate-200">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-amber-50 ring-2 ring-amber-200">
            <VerdictIcon level="suspicious" className="h-8 w-8 stroke-amber-600" />
          </div>
          <h1 className="mt-5 text-xl font-bold text-slate-900">Cần quyền Quản trị viên</h1>
          <p className="mt-2 text-sm leading-relaxed text-slate-600">
            WinCheck phải chạy với quyền Admin mới đọc được đầy đủ thông tin bản quyền và
            dấu vết kích hoạt. Bấm nút bên dưới để cấp quyền, ứng dụng sẽ tự khởi chạy lại.
          </p>
          <button
            onClick={() => Elevate(lines)}
            className="mt-6 w-full rounded-lg bg-brand-600 px-4 py-3 text-sm font-semibold text-white hover:bg-brand-700"
          >
            ⚡ Cấp quyền Admin và khởi chạy lại
          </button>
          <p className="mt-3 text-xs text-slate-400">Windows sẽ hiện hộp thoại UAC để bạn xác nhận.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      {/* ── Header ── */}
      <header className="flex-none border-b border-slate-200 bg-white">
        <div className="mx-auto flex h-14 w-full max-w-[1560px] items-center gap-2 px-4 sm:px-6">
          <svg viewBox="0 0 48 48" className="h-7 w-7 flex-none">
            <rect x="3" y="3" width="42" height="42" rx="9" className="fill-brand-600" />
            <path d="M14 25l6 6 14-14" fill="none" stroke="#fff" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="text-[15px] font-bold text-slate-900">WinCheck</span>
          <span className="text-xs font-semibold text-slate-400">{S["AppVersion"]}</span>
          <div className="flex-1" />
          <span className="hidden rounded-full bg-emerald-50 px-2.5 py-1 text-[11px] font-bold text-emerald-700 ring-1 ring-emerald-200 sm:inline">ADMIN</span>
          <button className={btn} disabled={scanning} onClick={doScan}>⟳ <span className="hidden sm:inline">Quét lại</span></button>
          <button className={btn} onClick={() => setDrawer("tools")}>Công cụ</button>
          <button className={btn} onClick={() => setDrawer("log")}>
            Chi tiết <span className="ml-1 rounded-full bg-slate-100 px-1.5 text-[10px] font-bold text-slate-500">{lines.length}</span>
          </button>
        </div>
      </header>

      {/* ── Nội dung ── */}
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1560px] px-4 py-6 sm:px-6">
          {scanning || !verdict ? (
            <div className="flex flex-col items-center justify-center py-24 text-center">
              <div className="h-11 w-11 animate-spin rounded-full border-[3px] border-slate-200 border-t-brand-600" />
              <div className="mt-5 text-[15px] font-semibold text-slate-800">{S["V_Scanning"]}</div>
              <div className="mt-1.5 font-mono text-xs text-slate-400">{statusText}</div>
            </div>
          ) : (
            <>
              {/* Thẻ phán quyết */}
              <section className={"relative overflow-hidden rounded-xl bg-white shadow-sm ring-1 " + tone.ring} role="status" aria-live="polite">
                <div className={"absolute inset-y-0 left-0 w-1.5 " + tone.bar} />
                <div className={"flex flex-col gap-5 p-6 sm:flex-row sm:items-center sm:gap-7 sm:p-8 " + tone.soft}>
                  <div className={"flex h-20 w-20 flex-none items-center justify-center rounded-full bg-white ring-2 " + tone.ring}>
                    <VerdictIcon level={level} className={"h-10 w-10 " + (level === "clean" ? "stroke-emerald-600" : "stroke-red-600")} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h1 className={"text-2xl font-extrabold leading-tight tracking-tight sm:text-3xl " + tone.text}>{verdict.title}</h1>
                    {verdict.typeValue && (
                      <p className="mt-2.5 flex flex-wrap items-center gap-2 text-[15px] text-slate-800">
                        <span className={"rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 " + tone.chip}>{verdict.typeLabel}</span>
                        <span className="font-bold">{verdict.typeValue}</span>
                      </p>
                    )}
                    <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-slate-500">{verdict.summary}</p>
                  </div>
                  {verdict.count > 0 && (
                    <div className="flex-none text-center">
                      <div className={"text-4xl font-extrabold leading-none " + tone.text}>{verdict.count}</div>
                      <div className="mt-1.5 text-[10px] font-bold tracking-wider text-slate-400">DẤU HIỆU</div>
                    </div>
                  )}
                </div>
              </section>

              {/* Tab chuyển giữa Kiểm định, Thông tin hệ thống và Phần cứng */}
              <div className="mt-5 flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1 text-[13px] font-semibold">
                <button onClick={() => setTab("audit")}
                  className={"rounded-md px-4 py-1.5 transition " + (tab === "audit" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-700")}>
                  {S["V_TabAudit"]}
                </button>
                <button onClick={() => setTab("system")}
                  className={"rounded-md px-4 py-1.5 transition " + (tab === "system" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-700")}>
                  {S["V_TabSystem"]}
                </button>
                <button onClick={() => setTab("hardware")}
                  className={"rounded-md px-4 py-1.5 transition " + (tab === "hardware" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-700")}>
                  {S["V_TabHardware"]}
                </button>
              </div>

              {/* Khuyến nghị nổi bật (vd: cần thay key bản quyền) */}
              {tab === "audit" && verdict.rec && (
                <section className="mt-4 flex gap-3.5 rounded-xl border-l-4 border-amber-500 bg-amber-50 p-5 shadow-sm ring-1 ring-amber-200">
                  <svg viewBox="0 0 24 24" className="mt-0.5 h-6 w-6 flex-none stroke-amber-600" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
                  </svg>
                  <div className="min-w-0">
                    <h2 className="text-sm font-bold tracking-wide text-amber-800">⚠ {verdict.rec.title}</h2>
                    <p className="mt-1.5 text-[13px] leading-relaxed text-amber-900/90">{verdict.rec.text}</p>
                    <button onClick={() => runTool(4)} className="mt-3 rounded-md bg-amber-600 px-3.5 py-2 text-[13px] font-semibold text-white hover:bg-amber-700">
                      Cài / thay key bản quyền mới →
                    </button>
                  </div>
                </section>
              )}

              {/* Thông tin hệ thống (tab Hệ thống) */}
              {tab === "system" && (
                <section className="mt-4 rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
                  <h2 className="mb-4 flex items-center gap-2 text-[11px] font-bold tracking-wider text-slate-400">
                    <span className="h-3.5 w-[3px] rounded-sm bg-brand-600" />{S["V_SystemInfo"]}
                  </h2>
                  <div className="grid grid-cols-1 gap-y-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
                    {verdict.facts.map((f, k) => (
                      <div key={k} className="min-w-0 border-slate-100 px-0 sm:px-4 sm:first:pl-0 xl:border-l xl:first:border-l-0">
                        <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{f.label}</div>
                        <div className={"selectable mt-1 break-words text-sm font-semibold " +
                          (f.tone === "ok" ? "text-emerald-700" : f.tone === "warn" ? "text-amber-700" : f.tone === "bad" ? "text-red-700" : "text-slate-800")}>
                          {f.value}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Thông tin phần cứng (kiểu CPU-Z, tab Phần cứng) */}
              {tab === "hardware" && verdict.hw && verdict.hw.length > 0 && (
                <section className="mt-4 rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
                  <h2 className="mb-4 flex items-center gap-2 text-[11px] font-bold tracking-wider text-slate-400">
                    <span className="h-3.5 w-[3px] rounded-sm bg-brand-600" />{S["V_HwTitle"]}
                  </h2>
                  <div className="grid grid-cols-1 gap-x-8 gap-y-5 lg:grid-cols-2">
                    {verdict.hw.map((g, gi) => (
                      <div key={gi} className="min-w-0">
                        <div className="mb-2 text-[11px] font-bold uppercase tracking-wide text-brand-700">{g.title}</div>
                        <dl className="space-y-1.5">
                          {g.items.map((it, ii) => (
                            <div key={ii} className="flex items-baseline justify-between gap-4 border-b border-slate-50 pb-1.5 last:border-0">
                              <dt className="flex-none text-[12px] text-slate-400">{it.label}</dt>
                              <dd className="selectable min-w-0 break-words text-right text-[13px] font-semibold text-slate-700">{it.value}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Key Windows trên máy (đầy đủ nếu có) */}
              {tab === "audit" && verdict.keys.length > 0 && (
                <section className="mt-4 rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
                  <h2 className="mb-3 flex items-center gap-2 text-[11px] font-bold tracking-wider text-slate-400">
                    <span className="h-3.5 w-[3px] rounded-sm bg-brand-600" />{S["V_KeysTitle"]}
                  </h2>
                  <div className="space-y-2.5">
                    {verdict.keys.map((k, i) => (
                      <div key={i} className="flex flex-col gap-1.5 border-b border-slate-100 pb-2.5 last:border-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
                        <div className="min-w-0">
                          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{k.label}</div>
                          <div className="selectable mt-0.5 break-all font-mono text-[15px] font-semibold text-slate-800">{k.value}</div>
                        </div>
                        {k.note && (
                          <span className={"flex-none whitespace-nowrap rounded px-2 py-0.5 text-[11px] font-semibold ring-1 " +
                            (k.tone === "bad" ? "bg-red-50 text-red-700 ring-red-200" : k.tone === "warn" ? "bg-amber-50 text-amber-700 ring-amber-200" : k.tone === "ok" ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-slate-100 text-slate-600 ring-slate-200")}>
                            {k.note}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                  <p className="mt-3 text-xs text-slate-400">
                    {verdict.keys.some((k) => k.value.includes("XXXXX-XXXXX")) ? S["V_KeyMaskedNote"] : S["V_KeyFullNote"]}
                  </p>
                </section>
              )}

              {/* Bảng tình trạng kiểm tra (tab Kiểm định) */}
              {tab === "audit" && (
              <section className="mt-4 overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-slate-200">
                <h2 className="flex items-center gap-2 px-5 pt-5 pb-3 text-[11px] font-bold tracking-wider text-slate-400 sm:px-6">
                  <span className="h-3.5 w-[3px] rounded-sm bg-brand-600" />{S["V_ChkTitle"]}
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-left text-[13px]">
                    <thead>
                      <tr className="border-y border-slate-100 bg-slate-50 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        <th className="px-5 py-2 sm:px-6">{S["V_ChkColName"]}</th>
                        <th className="px-3 py-2">{S["V_ChkColStatus"]}</th>
                        <th className="px-3 py-2 pr-5 sm:pr-6">{S["V_ChkColDetail"]}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                      {verdict.checks.map((c, k) => (
                        <tr key={k} className={c.status === "detected" ? "bg-red-50/40" : c.status === "warn" ? "bg-amber-50/40" : ""}>
                          <td className="whitespace-nowrap px-5 py-2.5 font-medium text-slate-800 sm:px-6">{c.name}</td>
                          <td className="px-3 py-2.5"><StatusBadge status={c.status} text={c.statusText} /></td>
                          <td className="selectable px-3 py-2.5 pr-5 text-slate-500 sm:pr-6">{c.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
              )}

              {/* Dấu hiệu (tab Kiểm định) */}
              {tab === "audit" && verdict.count > 0 && (
                <section className="mt-4 rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
                  <h2 className="mb-3 flex items-center gap-2 text-[11px] font-bold tracking-wider text-slate-400">
                    <span className="h-3.5 w-[3px] rounded-sm bg-brand-600" />{S["V_IndicatorsTitle"]}
                  </h2>
                  {crit.length > 0 && <div className="mb-1.5 mt-3 text-[11px] font-bold text-slate-400">Nghiêm trọng ({crit.length})</div>}
                  {crit.map((i, k) => (
                    <div key={"c" + k} className="flex items-baseline gap-3 border-b border-dashed border-slate-100 py-2 text-[13px] leading-relaxed text-slate-800 last:border-0">
                      <span className="h-1.5 w-1.5 flex-none rounded-full bg-red-600" />{i.text}
                    </div>
                  ))}
                  {warn.length > 0 && <div className="mb-1.5 mt-3 text-[11px] font-bold text-slate-400">Cảnh báo ({warn.length})</div>}
                  {warn.map((i, k) => (
                    <div key={"w" + k} className="flex items-baseline gap-3 border-b border-dashed border-slate-100 py-2 text-[13px] leading-relaxed text-slate-800 last:border-0">
                      <span className="h-1.5 w-1.5 flex-none rounded-full bg-amber-500" />{i.text}
                    </div>
                  ))}
                </section>
              )}

              {tab === "audit" && (
                <p className="mt-4 max-w-4xl text-xs leading-relaxed text-slate-400">{verdict.limits}</p>
              )}
            </>
          )}
        </div>
      </main>

      {/* ── Thanh trạng thái ── */}
      <footer className="flex-none border-t border-slate-200 bg-white">
        <div className="mx-auto flex h-9 w-full max-w-[1560px] items-center gap-2.5 px-4 text-[11px] text-slate-400 sm:px-6">
          <span className={"h-2 w-2 flex-none rounded-full " + (scanning ? "animate-pulse bg-amber-500" : "bg-emerald-500")} />
          <span className="truncate">{scanning ? S["V_Scanning"] : statusText || S["Ready"]}</span>
        </div>
      </footer>

      {/* ── Ngăn kéo ── */}
      {drawer && <div className="fixed inset-0 z-30 bg-slate-900/30" onClick={() => setDrawer(null)} />}
      {drawer && (
        <aside className={"fixed inset-y-0 right-0 z-40 flex flex-col border-l border-slate-200 bg-white shadow-2xl " + (drawer === "log" ? "w-full max-w-3xl" : "w-full max-w-sm")}>
          <div className="flex h-14 flex-none items-center gap-2 border-b border-slate-200 px-4">
            <h3 className="text-sm font-bold text-slate-900">{drawer === "log" ? S["V_ShowDetails"] : S["V_AdvancedTools"]}</h3>
            <div className="flex-1" />
            <button className={btn} onClick={() => setDrawer(null)}>Đóng ✕</button>
          </div>
          {drawer === "log" ? (
            <div ref={logRef} className="selectable flex-1 overflow-auto p-4 font-mono text-[11.5px] leading-relaxed">
              {lines.map((l, i) => <LogRow key={i} l={l} />)}
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-4">
              {/* Dọn sạch crack — hành động chính, một chạm */}
              <div className="mb-2 text-[10px] font-bold tracking-wider text-red-600">🧹 {S["V_ToolsCleanHead"]}</div>
              <ToolBtn danger disabled={scanning} onClick={() => runTool(8)} title={S["V_ToolClean"]} desc={S["V_ToolCleanDesc"]} />
              <ToolBtn danger disabled={scanning} onClick={() => runTool(9)} title={S["V_ToolCleanOffice"] || "Gỡ sạch key Office lậu"} desc={S["V_ToolCleanOfficeDesc"] || "Xóa máy chủ KMS và gỡ sạch key Office lậu (2010 - 2024, 365)"} />

              {/* Thay đổi key bản quyền */}
              <div className="mb-2 mt-5 text-[10px] font-bold tracking-wider text-red-600">⚠ {S["V_ToolsChangeHead"]}</div>
              <ToolBtn danger disabled={scanning} onClick={() => runTool(4)} title={S["V_ToolInstallKey"]} desc={S["V_ToolInstallDesc"]} />
              <ToolBtn danger disabled={scanning} onClick={() => runTool(5)} title={S["V_ToolRemoveKey"]} desc={S["V_ToolRemoveDesc"]} />
            </div>
          )}
        </aside>
      )}

      {/* ── Hộp thoại ── */}
      {dialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4" onClick={() => setDialog(null)}>
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            {dialog.kind === "confirm" ? (
              <>
                <h2 className="text-base font-bold text-slate-900">Xác nhận</h2>
                <p className="mt-2 whitespace-pre-wrap text-[13px] leading-relaxed text-slate-600">{dialog.msg}</p>
                <div className="mt-6 flex justify-end gap-2">
                  <button className={btn} onClick={() => setDialog(null)}>Hủy</button>
                  <button className="h-8 rounded-md bg-red-600 px-4 text-[13px] font-semibold text-white hover:bg-red-700" onClick={dialog.run}>Đồng ý</button>
                </div>
              </>
            ) : (
              <>
                <h2 className="text-base font-bold text-slate-900">Nhập Key Bản Quyền</h2>
                <p className="mt-2 whitespace-pre-wrap text-[13px] text-slate-600">{S["O4_Prompt"]}</p>
                <input autoFocus value={keyInput} onChange={(e) => setKeyInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") doRun(4, { key: keyInput, confirm: true }); if (e.key === "Escape") setDialog(null); }}
                  className="selectable mt-3 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-brand-500" />
                <div className="mt-6 flex justify-end gap-2">
                  <button className={btn} onClick={() => setDialog(null)}>Hủy</button>
                  <button className="h-8 rounded-md bg-brand-600 px-4 text-[13px] font-semibold text-white hover:bg-brand-700"
                    onClick={() => doRun(4, { key: keyInput, confirm: true })}>Xác nhận</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
