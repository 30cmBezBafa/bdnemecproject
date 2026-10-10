// ==UserScript==
// @name         VIN Normy Agent — SuperETKA/ELSA/APOS → Supabase
// @namespace    https://github.com/OWNER/vin-normy
// @version      1.0.0
// @description  Перехватчик: читает открытые страницы SuperETKA (поиск VIN, ELSA-идентификация, APOS-нормы) и льёт структурированную карточку авто + операции норм времени в общую Supabase-базу. Работает в уже залогиненной сессии сотрудника, пароль ETKA не хранит. Лимит SuperETKA не тратит сам — только читает то, что открыл человек.
// @author       vin-normy
// @license      MIT
// @match        https://superetka.com/*
// @match        http://superetka.com/*
// @run-at       document-idle
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_registerMenuCommand
// @connect      superetka.com
// @connect      supabase.co
// @connect      *.supabase.co
// ==/UserScript==

/* ============================================================================
 * VIN Normy Agent (вариант B)
 * ----------------------------------------------------------------------------
 * Что делает:
 *   1) На странице поиска /vins/  — парсит строки результата, определяет бренд
 *      по WMI, фильтрует по белому списку (VW/Audi/Skoda/Seat/Porsche/BMW/
 *      Mini/Mercedes/Alpina), для валидных «наших» VIN подтягивает ELSA-
 *      идентификацию (ajaxIdentCarPrint) и пишет/дополняет карточку авто.
 *   2) На странице APOS (нормы времени) — паржит текстовый дамп работ,
 *      вставляет операции норм времени (один раз на VIN, без дублей) и сырой
 *      снимок текста.
 *   3) Пишет в Supabase под ЛИЧНЫМ логином сотрудника → триггеры RLS-аудита
 *      сами фиксируют в audit_log, КТО собрал VIN (Шпехт/Цыбайло/Ванжа/...).
 *
 * Чего НЕ делает (осознанно, v1):
 *   - не тратит лимит SuperETKA и не знает, списался ли он (учёт лимита —
 *     задача фронта A / воркера, не перехватчика);
 *   - не считает applicability APOS к авто (это фронт по specs); операции
 *     льются «как есть» + токены условий в jsonb;
 *   - не дописывает specs уже существующей карточки при повторном просмотре
 *     (чтобы не затереть ручные уточнения фронта) — дописывает только
 *     идентификаторы (brand/model/generation/year/engine_code/gearbox_code/
 *     drive), а полный raw всегда кладётся в source_snapshots для переобработки.
 *
 * Безопасность:
 *   - пароль Supabase сотрудника живёт ТОЛЬКО в локальном GM-хранилище
 *     браузера (GM_setValue), в репо и на superetka не уходит;
 *   - anon-ключ Supabase публичный, защита на RLS;
 *   - логин/пароль ETKA агенту не нужны вообще — он читает твою сессию.
 * ============================================================================ */

(function () {
  "use strict";

  /* ----------------------------- Константы -------------------------------- */

  const PARSER_VERSION_IDENT = "ident-1.1";
  const PARSER_VERSION_APOS  = "apos-text-1.1";
  const PARSER_VERSION_SEARCH = "search-1.0";

  const WHITELIST_CODES = ["VW","Audi","Skoda","Seat","Porsche","BMW","Mini","Mercedes","Alpina"];

  // Компактная WMI -> brand_code. Всё, чего тут нет и что не резолвится по
  // make из ident, уходит в unsupported_brand (не льём дальше).
  const WMI_BRAND = {
    XW8:"VW", WVW:"VW", "1VW":"VW", "2VW":"VW", "3VW":"VW", LSV:"VW", LFV:"VW",
    WAU:"Audi", WUA:"Audi",
    TMB:"Skoda", TMU:"Skoda",
    VSS:"Seat", // прим.: VSS часто LADA; если ident скажет иначе — перебьём по make
    "9BW":"Porsche", WP0:"Porsche", WP1:"Porsche",
    WBA:"BMW", WBS:"BMW", WBY:"Mini",
    WDB:"Mercedes", WDC:"Mercedes", WDD:"Mercedes",
    // Alpina редко в WMI-префиксах, ловится по make из ident
  };

  // Регионы-карантин по первому символу VIN (не льём в лимитную логику фронта;
  // агент всё равно запишет карточку, но с пометкой в meta snapshot).
  const REGION_QUARANTINE = { "3":"MX", "2":"CA" }; // Мексика/Канада — спорные
  const REGION_BLOCK      = { "L":"CN" };           // Китай — AI-дек не работает

  /* ------------------------- Нормализация текста -------------------------- */

  const norm = (s) => String(s ?? "").replace(/ё/g, "е").replace(/\s+/g, " ").trim();
  const lower = (s) => norm(s).toLowerCase();
  const round = (n, d = 2) => { const x = Number(n); return Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : 0; };

  const VIN_RE = /^[A-HJ-NPR-Z0-9]{17}$/;
  const YEAR_RE = /\b(19[89]\d|20[0-4]\d)\b/;

  function validVin(v) { return VIN_RE.test(String(v || "").toUpperCase()); }
  function brandByWmi(vin) { return WMI_BRAND[String(vin || "").slice(0, 3).toUpperCase()] || null; }

  /* ---------------------------- HTTP (GM) --------------------------------- */
  // GM_xmlhttpRequest обходит CORS/CSP страницы; все запросы — через него.

  function http(method, url, headers = {}, body = null) {
    return new Promise((resolve) => {
      GM_xmlhttpRequest({
        method, url,
        headers,
        data: body == null ? undefined : (typeof body === "string" ? body : JSON.stringify(body)),
        timeout: 20000,
        onload: (r) => {
          let json = null;
          try { json = JSON.parse(r.responseText); } catch (_) { /* не json */ }
          resolve({ status: r.status, text: r.responseText || "", json });
        },
        onerror: () => resolve({ status: 0, text: "network error", json: null }),
        ontimeout: () => resolve({ status: 0, text: "timeout", json: null }),
      });
    });
  }

  /* --------------------------- Настройки UI ------------------------------- */
  // Компактный оверлей-форма (пароль не светим через prompt()).

  const CFG = {
    url:    GM_getValue("sb_url", ""),
    anon:   GM_getValue("sb_anon", ""),
    email:  GM_getValue("sb_email", ""),   // вида zamataev@service.local
    pass:   GM_getValue("sb_pass", ""),
  };
  let TOKEN = null; // { access, refresh, expiresAt }

  function loadToken() {
    try { TOKEN = JSON.parse(GM_getValue("sb_token", "null")); } catch (_) { TOKEN = null; }
  }
  function saveToken() { GM_setValue("sb_token", JSON.stringify(TOKEN)); }
  function tokenAlive() { return TOKEN && TOKEN.access && TOKEN.expiresAt > Date.now() + 15000; }

  function openSettings() {
    const old = document.getElementById("vna-panel");
    if (old) old.remove();
    const p = document.createElement("div");
    p.id = "vna-panel";
    p.style.cssText =
      "position:fixed;top:12px;right:12px;z-index:2147483647;width:300px;" +
      "background:#101826;color:#e6edf7;border:1px solid #2b3a55;border-radius:12px;" +
      "padding:14px;font:13px/1.4 system-ui,Arial,sans-serif;box-shadow:0 12px 34px rgba(0,0,0,.5)";
    p.innerHTML = `
      <div style="font-weight:700;margin-bottom:8px">VIN Normy Agent — настройки Supabase</div>
      <label style="display:block;margin:6px 0 2px;color:#9fb0c9">Project URL</label>
      <input id="vna-url" value="${escapeAttr(CFG.url)}" style="${inp()}">
      <label style="display:block;margin:6px 0 2px;color:#9fb0c9">Anon key</label>
      <input id="vna-anon" value="${escapeAttr(CFG.anon)}" style="${inp()}">
      <label style="display:block;margin:6px 0 2px;color:#9fb0c9">Логин (email вида fam@service.local)</label>
      <input id="vna-email" value="${escapeAttr(CFG.email)}" style="${inp()}">
      <label style="display:block;margin:6px 0 2px;color:#9fb0c9">Пароль</label>
      <input id="vna-pass" type="password" value="${escapeAttr(CFG.pass)}" style="${inp()}">
      <div style="display:flex;gap:6px;margin-top:10px">
        <button id="vna-save" style="${btn()}">Сохранить и войти</button>
        <button id="vna-close" style="${btn('#334155')}">Закрыть</button>
      </div>
      <div id="vna-msg" style="margin-top:8px;color:#fbbf24;min-height:1em"></div>
    `;
    document.body.appendChild(p);
    p.querySelector("#vna-close").onclick = () => p.remove();
    p.querySelector("#vna-save").onclick = async () => {
      CFG.url   = p.querySelector("#vna-url").value.trim().replace(/\/+$/, "");
      CFG.anon  = p.querySelector("#vna-anon").value.trim();
      CFG.email = p.querySelector("#vna-email").value.trim().toLowerCase();
      CFG.pass  = p.querySelector("#vna-pass").value;
      GM_setValue("sb_url", CFG.url); GM_setValue("sb_anon", CFG.anon);
      GM_setValue("sb_email", CFG.email); GM_setValue("sb_pass", CFG.pass);
      const msg = p.querySelector("#vna-msg");
      msg.textContent = "Вхожу...";
      const ok = await login(true);
      msg.textContent = ok ? "✅ Вошёл, агент активен" : "❌ Не удалось войти (проверь URL/key/логин/пароль)";
      if (ok) setTimeout(() => p.remove(), 1200);
    };
  }
  const inp = () => "width:100%;box-sizing:border-box;padding:6px 8px;border:1px solid #2b3a55;border-radius:8px;background:#0b1220;color:#e6edf7";
  const btn = (bg = "#2563eb") => `padding:7px 12px;border:0;border-radius:8px;background:${bg};color:#fff;font-weight:600;cursor:pointer`;
  function escapeAttr(s) { return String(s ?? "").replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;"); }

  /* ------------------------------ Auth Supabase --------------------------- */

  async function login(force = false) {
    if (!CFG.url || !CFG.anon || !CFG.email || !CFG.pass) { setStatus("не настроен — открой ⚙"); return false; }
    if (!force && tokenAlive()) return true;

    // refresh, если есть и не просим force
    if (!force && TOKEN && TOKEN.refresh) {
      const r = await http("POST", `${CFG.url}/auth/v1/token?grant_type=refresh_token`,
        { "apikey": CFG.anon, "Content-Type": "application/json" },
        { refresh_token: TOKEN.refresh });
      if (r.status === 200 && r.json?.access_token) {
        TOKEN = { access: r.json.access_token, refresh: r.json.refresh_token || TOKEN.refresh,
                  expiresAt: Date.now() + (r.json.expires_in || 3600) * 1000 };
        saveToken(); return true;
      }
    }

    const r = await http("POST", `${CFG.url}/auth/v1/token?grant_type=password`,
      { "apikey": CFG.anon, "Content-Type": "application/json" },
      { email: CFG.email, password: CFG.pass });

    if (r.status === 200 && r.json?.access_token) {
      TOKEN = { access: r.json.access_token, refresh: r.json.refresh_token,
                expiresAt: Date.now() + (r.json.expires_in || 3600) * 1000 };
      saveToken();
      setStatus("онлайн: " + CFG.email.split("@")[0]);
      await loadDictionaries();
      return true;
    }
    TOKEN = null; saveToken();
    setStatus("ошибка входа: " + (r.json?.msg || r.status));
    return false;
  }

  async function ensureAuth() {
    if (tokenAlive()) return true;
    return await login(false);
  }

  function restHeaders(extra = {}) {
    return Object.assign({
      "apikey": CFG.anon,
      "Authorization": "Bearer " + (TOKEN?.access || ""),
      "Content-Type": "application/json",
    }, extra);
  }

  /* --------------------- Словари из Supabase (накопление) ----------------- */
  // Тянем один раз за сессию, чтобы подтверждения сотрудников влияли на парсинг.

  const DICT = { engine: {}, gearbox: {}, model: {}, pr: {}, brandAlias: {} };

  async function loadDictionaries() {
    try {
      const [eng, gb, mdl, pr, br] = await Promise.all([
        sbGet("/rest/v1/engine_dict?select=*"),
        sbGet("/rest/v1/gearbox_dict?select=*"),
        sbGet("/rest/v1/model_generation_dict?select=*"),
        sbGet("/rest/v1/pr_code_dict?select=*"),
        sbGet("/rest/v1/brand_whitelist?select=code,name,match_aliases"),
      ]);
      DICT.engine = indexBy(eng, "code");
      DICT.gearbox = indexBy(gb, "code");
      DICT.model = indexBy(mdl, "vtyp");
      DICT.pr = indexBy(pr, "code");
      DICT.brandAlias = {};
      (br || []).forEach(b => (b.match_aliases || []).forEach(a => DICT.brandAlias[lower(a)] = b.code));
    } catch (e) { console.warn("[vna] dictionaries load failed", e); }
  }
  const indexBy = (arr, key) => Object.fromEntries((arr || []).map(o => [o[key], o]));

  async function sbGet(path) {
    if (!(await ensureAuth())) return null;
    const r = await http("GET", CFG.url + path, restHeaders());
    if (r.status === 401) { if (await login(true)) return sbGet(path); return null; }
    return r.status === 200 ? r.json : null;
  }
  async function sbPost(path, payload, prefer = "return=representation") {
    if (!(await ensureAuth())) return null;
    const r = await http("POST", CFG.url + path, restHeaders({ "Prefer": prefer }), payload);
    if (r.status === 401) { if (await login(true)) return sbPost(path, payload, prefer); }
    return { status: r.status, json: r.json, text: r.text };
  }
  async function sbPatch(path, payload) {
    if (!(await ensureAuth())) return null;
    const r = await http("PATCH", CFG.url + path, restHeaders({ "Prefer": "return=minimal" }), payload);
    if (r.status === 401) { if (await login(true)) return sbPatch(path, payload); }
    return { status: r.status, json: r.json, text: r.text };
  }

  /* ======================= ПАРСЕР: поиск /vins/ =========================== */
  // Хрупко: колонок-заголовков нет, цепляемся по индексу + эвристики.

  function parseSearchPage() {
    const tables = Array.from(document.querySelectorAll("table.table"));
    const rows = [];
    tables.forEach(t => t.querySelectorAll("tr").forEach(tr => {
      const td = Array.from(tr.children).map(c => norm(c.textContent));
      const imgs = Array.from(tr.querySelectorAll("img")).map(i => (i.getAttribute("src") || "").toLowerCase());
      if (td.length >= 10 && VIN_RE.test((td[1] || "").toUpperCase())) {
        rows.push({
          vin: td[1].toUpperCase(),
          model_code: td[2] || "",
          engine_code: (td[3] || "").toUpperCase(),
          engine_desc: td[4] || "",
          gearbox_code: (td[5] || "").toUpperCase(),
          awd: imgs.some(s => s.includes("quattro")),
          year: (td.find(c => YEAR_RE.test(c)) || "").match(YEAR_RE)?.[1] || "",
        });
      }
    }));
    return rows;
  }

  /* ==================== ПАРСЕР: ELSA-идентификация ======================== */
  // Мультиязычные подписи (RU/DE/EN) + эвристики; значения-коды языконезависимы.

  const IDENT_LABELS = {
    model_label:   ["обозначение модели","ausstattungsbezeichnung","bargain designation","trim designation"],
    model_code:    ["модель","modell","model"],
    production_date:["дата производства","herstellungsdatum","date of manufacture"],
    delivery_date: ["дата поставки","auslieferungsdatum","delivery date"],
    model_year:    ["модельный год","modelljahr","model year"],
    trade_code:    ["торг.обозн.","handelsbezeichnung","trade designation","vtyp"],
    vin:           ["vin-номер","fin","vin nummer","vin-number"],
    engine_raw:    ["код двигателя","motorkennbuchstabe","motorcode","engine code","motore"],
    gearbox_raw:   ["код кп","getriebe","getriebecode","transmission code","at kp"],
    interior:      ["интерьер","innenraumverkleidung","interior"],
    roof_paint:    ["цвет крыши / № краски","dachfarbe","roof color"],
    ext_paint:     ["наружная краска / № краски","außenlackierung","exterior paint"],
  };

  function identLabelKey(labelText) {
    const l = lower(labelText);
    for (const [k, arr] of Object.entries(IDENT_LABELS)) {
      if (arr.some(a => l === lower(a) || l.includes(lower(a)))) return k;
    }
    return null;
  }

  function parseIdentHtml(html) {
    const doc = new DOMParser().parseFromString(html || "", "text/html");
    const ident = {};
    doc.querySelectorAll("tr").forEach(tr => {
      if (tr.children.length !== 2) return;
      const key = identLabelKey(tr.children[0].textContent);
      const val = norm(tr.children[1].textContent);
      if (key && val && !(key in ident)) ident[key] = val;
    });

    // PR-строки: 3 ячейки [группа | код | текст], код = 3 символа [0-9A-Z]
    const prKnown = [], prUnknown = [];
    const PR_RE = /^[0-9A-Z]{3}$/i;
    doc.querySelectorAll("tr").forEach(tr => {
      if (tr.children.length !== 3) return;
      const group = norm(tr.children[0].textContent);
      const code  = norm(tr.children[1].textContent).toUpperCase();
      const text  = norm(tr.children[2].textContent);
      if (!group || lower(group) === "pr") return;
      if (!PR_RE.test(code)) return;
      (DICT.pr[code] ? prKnown : prUnknown).push({ group, code, text });
    });

    return buildSpecs(ident, prKnown, prUnknown);
  }

  function codeFromRaw(raw) {
    const m = String(raw || "").trim().match(/^([0-9A-Z]{2,5})\b/i);
    return m ? m[1].toUpperCase() : norm(raw).toUpperCase();
  }

  function buildSpecs(ident, prKnown, prUnknown) {
    const s = {
      make:"", model:"", generation:"",
      engine_code:"", engine_desc:"", timing_drive:"", displacement_cc:null,
      power_kw:null, power_hp:null, torque_nm:null, fuel:"",
      gearbox_code:"", gearbox_marker:"", gearbox_type:"", gearbox_gears:null,
      drive:"front", awd_type:"",
      susp_front:"", susp_rear:"", handbrake:"",
      brakes_front:"", brakes_rear:"", steering:"",
      body_type:"", doors:null, model_year:null, trade_code:"",
      production_date:"", missing:[], confidence:0,
    };

    s.trade_code = ident.trade_code || "";
    s.production_date = ident.production_date || "";
    const ym = (ident.model_year || "").match(YEAR_RE);
    s.model_year = ym ? Number(ym[1]) : null;

    if (ident.engine_raw) { s.engine_code = codeFromRaw(ident.engine_raw); s.engine_desc = ident.engine_raw; }
    if (ident.gearbox_raw) { s.gearbox_code = codeFromRaw(ident.gearbox_raw); s.gearbox_marker = ident.gearbox_raw; }

    // бренд по make-подписи если есть, иначе позже по WMI
    if (ident.model_label) s.make = ident.model_label;

    // словари из БД
    const eng = DICT.engine[s.engine_code];
    if (eng) {
      s.timing_drive = eng.timing_drive || ""; s.displacement_cc = eng.displacement_cc ?? null;
      s.power_kw = eng.power_kw ?? null; s.power_hp = eng.power_hp ?? null;
      s.torque_nm = eng.torque_nm ?? null; s.fuel = eng.fuel || "";
    } else if (s.engine_code) s.missing.push("engine_dict:" + s.engine_code);

    const gbKeys = [s.gearbox_code, s.gearbox_marker, ...prKnown.map(p => p.code)]
      .flatMap(x => String(x).split(/[\s,]+/)).filter(Boolean);
    let gb = null; for (const k of gbKeys) if (DICT.gearbox[k]) { gb = DICT.gearbox[k]; break; }
    if (gb) { s.gearbox_type = gb.type || ""; s.gearbox_gears = gb.gears ?? null; }
    else if (s.gearbox_code || s.gearbox_marker) s.missing.push("gearbox_dict:" + (s.gearbox_code || s.gearbox_marker));

    const vtyp = (s.trade_code || "").slice(0, 3);
    const mdl = DICT.model[vtyp];
    if (mdl) { s.model = mdl.model; s.generation = mdl.generation; }
    else if (s.make) { s.model = s.make; s.missing.push("model_dict:" + vtyp); }

    for (const p of prKnown) {
      const map = DICT.pr[p.code];
      if (map) s[map.field] = map.value;
    }

    const awdText = prKnown.some(p => /quattro|4x4|4 motion/.test(lower(p.text)));
    if (awdText || s.drive === "awd_quattro") { s.drive = "awd"; s.awd_type = s.awd_type || "quattro"; }
    else s.drive = "front";
    if (s.rear_axle === "torsion_beam_std") s.susp_rear = "torsion_beam";

    ["timing_drive","torque_nm","gearbox_type","handbrake","susp_front"].forEach(k => { if (!s[k]) s.missing.push(k); });

    const HARD = ["engine_code","timing_drive","displacement_cc","power_kw","torque_nm",
                  "gearbox_type","gearbox_gears","drive","susp_front","susp_rear",
                  "handbrake","brakes_front","brakes_rear","steering","generation"];
    const filled = HARD.filter(k => s[k] !== "" && s[k] != null && s[k] !== 0).length;
    s.confidence = round(filled / HARD.length, 2);

    delete s.rear_axle;
    return { specs: s, ident, prKnown, prUnknown };
  }

  /* ====================== ПАРСЕР: APOS (текст) ============================ */
  // Кирпич №2, встроен как функция; многоязычные токены условий (RU/DE/EN).

  const OP_RE = /^(\d{2})\s+(\d{2})\s+(\d{2})\s+(\d{2,3}):?\s+(\d+)\s+(\d+)\s+(.+)$/;
  const CAT_RE = /^(трансмиссия|ходовая часть|кузов|отопление, вентиляция, кондиционирование|электрооборудование|двигатель|getriebe|fahrwerk|karosserie|heizung|elektrik|moteur|chassis|body|electrical)$/i;
  const TERM_RE = /^(узлы\/рем\. группы|объем заказа|img\s+\d|nodes\/|order volume)$/i;
  const VINMETA_RE = /^[A-HJ-NPR-Z0-9]{17}\s/i;

  function aposTokens(text) {
    const t = lower(text);
    const tok = { liters:[], fuels:[], timings:[], gearboxTypes:[], gearboxCodes:[],
                  flags:{ noClimate:false, predecessor:false, including:false, related:false } };
    for (const m of t.matchAll(/(\d[.,]\d)\s*(?:л|l\b)/g)) { const v = Number(m[1].replace(",", ".")); if (Number.isFinite(v)) tok.liters.push(v); }
    if (/\b(mpi|tsi|tfsi|si|benzin|petrol|port fuel|впрыск|einspritz)\b/.test(t)) tok.fuels.push("petrol");
    if (/\b(tdi|sdi|pd|дизел|diesel)\b/.test(t)) tok.fuels.push("diesel");
    if (/зубчат[ыи]м ремн|ремен[ьё]? грм|belt|zahnriemen/.test(t)) tok.timings.push("belt");
    if (/цеп[ьё]|chain|steuerkette/.test(t)) tok.timings.push("chain");
    if (/акп|автомат|automatic|tiptronic|automatik/.test(t)) tok.gearboxTypes.push("automatic");
    if (/мкпп|механическ|manual|schaltgetriebe/.test(t)) tok.gearboxTypes.push("manual");
    if (/dsg|робот|dual.?clutch|doppelkupplung/.test(t)) tok.gearboxTypes.push("dct");
    tok.gearboxCodes = [...new Set((t.toUpperCase().match(/\b(?:0[0-9A-Z]{2}|[A-Z]{2}[0-9]{3}(?:-[0-9A-Z]+)?|D[QL][0-9]{3}(?:-[0-9A-Z]+)?)\b/g) || []))];
    tok.flags.noClimate = /без климат|without air|no air|ohne klim|klima(?:anlage)? fehl/.test(t);
    tok.flags.predecessor = /предшественник|vorgänger|predecessor/.test(t);
    tok.flags.including = /включая|inkl|including/.test(t);
    tok.flags.related = /связанная работа|verbundene|related work/.test(t);
    return tok;
  }

  function parseAposText(rawText) {
    const lines = String(rawText || "").replace(/\r\n?/g, "\n").split("\n")
      .map(l => l.replace(/\t/g, " ").replace(/\s+/g, " ").trim()).filter(Boolean);
    const ops = []; let cur = null, started = false;
    const push = () => { if (cur) { ops.push(cur); cur = null; } };
    for (const line of lines) {
      const lo = lower(line);
      if (TERM_RE.test(lo) || VINMETA_RE.test(line)) { push(); break; }
      if (CAT_RE.test(lo)) { push(); started = true; continue; }
      const m = line.match(OP_RE);
      if (m) {
        push();
        cur = { group_code:m[1], repair_group_code:m[2], position_code:m[3], work_code:m[4],
                minutes:Number(m[5]), factor:Number(m[6]), description:m[7].trim(), conditions:[] };
        started = true; continue;
      }
      if (!started) continue;
      if (cur) cur.conditions.push(line);
    }
    push();
    return ops.map(op => {
      const ct = op.conditions.join(" | ");
      return { ...op, conditions_text: ct, condition_tokens: aposTokens(ct),
               elapsed_hours: round(op.minutes / 60, 2), man_hours: round(op.minutes * op.factor / 60, 2) };
    });
  }

  function collectPageText() {
    // main + same-origin iframes (APOS может быть в фрейме)
    let txt = document.body ? document.body.innerText : "";
    document.querySelectorAll("iframe").forEach(f => {
      try { if (f.contentDocument?.body) txt += "\n" + f.contentDocument.body.innerText; } catch (_) {}
    });
    return txt;
  }

  /* ============================ Запись в Supabase ========================= */

  async function fetchIdentHtml(vin) {
    // same-origin запрос в той же сессии superetka (cookies подтянутся)
    const url = `https://superetka.com/etka/ajaxIdentCarPrint&lang=RU&vin=${encodeURIComponent(vin)}`;
    const r = await http("GET", url, { "Accept": "text/html" });
    return r.status === 200 ? r.text : "";
  }

  function currentVinFromPage() {
    const u = new URL(location.href);
    if (u.searchParams.get("vin")) return u.searchParams.get("vin").toUpperCase();
    const inp = document.querySelector("input#vin, input[name='vin']");
    if (inp?.value && VIN_RE.test(inp.value.toUpperCase())) return inp.value.toUpperCase();
    const m = (document.body.innerText || "").match(/[A-HJ-NPR-Z0-9]{17}/);
    return m ? m[0].toUpperCase() : "";
  }

  async function upsertVehicleFromIdent(vin, parsed, rawHtml) {
    const brand = brandByWmi(vin) || DICT.brandAlias[lower(parsed.specs.make)] || null;
    const whitelisted = brand && WHITELIST_CODES.includes(brand);
    const fmtOk = validVin(vin);

    const existing = await sbGet(`/rest/v1/vehicles?vin=eq.${encodeURIComponent(vin)}&select=id,specs,status,confirmed_at,deleted_at&limit=1`);
    const row = Array.isArray(existing) ? existing[0] : null;

    // snapshot идентификации — всегда (raw для переобработки)
    let snapId = null;
    const snap = await sbPost("/rest/v1/source_snapshots", [{
      vin, vin_id: row?.id || null, source_type: "superetka_elsa_ident",
      url: location.href, payload: rawHtml, parser_version: PARSER_VERSION_IDENT,
      meta: { brand, whitelisted, region: REGION_QUARANTINE[vin[0]] || REGION_BLOCK[vin[0]] || null },
    }]);
    if (snap?.json?.[0]?.id) snapId = snap.json[0].id;

    if (!fmtOk) {
      if (!row) await sbPost("/rest/v1/vehicles", [{ vin, format_valid:false, status:"invalid_format", brand_code:brand }]);
      return { vin, status:"invalid_format" };
    }
    if (!whitelisted) {
      if (!row) await sbPost("/rest/v1/vehicles", [{ vin, format_valid:true, status:"unsupported_brand", brand_code:brand }]);
      return { vin, status:"unsupported_brand" };
    }

    const sp = parsed.specs;
    const status = sp.confidence >= 0.8 && sp.missing.length === 0 ? "parsed" : "needs_confirmation";

    if (!row) {
      await sbPost("/rest/v1/vehicles", [{
        vin, brand_code: brand, format_valid: true, status,
        model: sp.model || null, generation: sp.generation || null, model_year: sp.model_year,
        engine_code: sp.engine_code || null, gearbox_code: sp.gearbox_code || null, drive: sp.drive || null,
        specs: sp, missing: sp.missing, confidence: sp.confidence,
        needs_confirmation: status === "needs_confirmation",
        source_summary: { ident_snapshot: snapId, brand_source: brandByWmi(vin) ? "wmi" : "make" },
      }]);
      return { vin, status, created:true };
    }

    // существующая карточка: дописываем ТОЛЬКО непустые идентификаторы,
    // не трогая specs/status/confirmed/missing (защита ручных уточнений фронта)
    const patch = {};
    if (brand) patch.brand_code = brand;
    if (sp.model) patch.model = sp.model;
    if (sp.generation) patch.generation = sp.generation;
    if (sp.model_year) patch.model_year = sp.model_year;
    if (sp.engine_code) patch.engine_code = sp.engine_code;
    if (sp.gearbox_code) patch.gearbox_code = sp.gearbox_code;
    if (sp.drive) patch.drive = sp.drive;
    if (snapId) patch.source_summary = Object.assign({}, row.specs?._ss || {}, { last_ident_snapshot: snapId });
    if (Object.keys(patch).length) await sbPatch(`/rest/v1/vehicles?vin=eq.${encodeURIComponent(vin)}`, patch);
    return { vin, status: row.status, updated:true };
  }

  async function insertAposOperations(vin, ops, rawText) {
    const veh = await sbGet(`/rest/v1/vehicles?vin=eq.${encodeURIComponent(vin)}&select=id&limit=1`);
    const vinId = Array.isArray(veh) ? veh[0]?.id : null;

    // дедуп: если для VIN уже есть apos-снимок — не вставляем повторно
    const prev = await sbGet(`/rest/v1/source_snapshots?vin_id=eq.${vinId}&source_type=eq.superetka_apos_text&select=id&limit=1`);
    if (Array.isArray(prev) && prev.length) return { vin, skipped_duplicate:true, count:0 };

    const snap = await sbPost("/rest/v1/source_snapshots", [{
      vin, vin_id: vinId, source_type: "superetka_apos_text",
      url: location.href, payload: rawText, parser_version: PARSER_VERSION_APOS, meta:{},
    }]);
    const snapId = snap?.json?.[0]?.id || null;

    const rows = ops.map(o => ({
      group_code:o.group_code, repair_group_code:o.repair_group_code,
      position_code:o.position_code, work_code:o.work_code,
      minutes:o.minutes, factor:o.factor, description:o.description,
      conditions: o.condition_tokens, context_model:null, context_engine:null, context_gearbox:null,
      source_snapshot_id: snapId, parser_version: PARSER_VERSION_APOS,
    }));
    if (rows.length) await sbPost("/rest/v1/apos_operations", rows);
    return { vin, count: rows.length, snapId };
  }

  /* ============================== Диспетчер =============================== */

  let scanning = false;
  async function scan() {
    if (scanning) return; scanning = true;
    try {
      if (!(await ensureAuth())) { setStatus("не авторизован — ⚙ Настройки"); return; }

      const path = location.pathname.toLowerCase();
      const isSearch = path.includes("/vins");
      const text = collectPageText();
      const looksApos = OP_RE.test(text.split("\n").find(l => OP_RE.test(l)) || "");

      if (isSearch) {
        const rows = parseSearchPage();
        if (!rows.length) { setStatus("поиск: строк результата нет"); return; }
        let done = 0, skip = 0;
        for (const r of rows) {
          const brand = brandByWmi(r.vin);
          if (!brand || !WHITELIST_CODES.includes(brand) || !validVin(r.vin)) { skip++; continue; }
          const html = await fetchIdentHtml(r.vin);
          if (html) {
            const parsed = parseIdentHtml(html);
            // подстраховка: если ident не дал код движка/КП — берём из search-строки
            if (!parsed.specs.engine_code && r.engine_code) parsed.specs.engine_code = r.engine_code;
            if (!parsed.specs.gearbox_code && r.gearbox_code) parsed.specs.gearbox_code = r.gearbox_code;
            if (!parsed.specs.model_year && r.year) parsed.specs.model_year = Number(r.year);
            if (r.awd) { parsed.specs.drive = "awd"; parsed.specs.awd_type = parsed.specs.awd_type || "quattro"; }
            await upsertVehicleFromIdent(r.vin, parsed, html);
            done++;
          }
          await sleep(300); // троттлинг, не душим superetka
        }
        setStatus(`поиск: обработано ${done}, пропущено (не наш бренд/битый) ${skip}`);
        return;
      }

      if (looksApos) {
        const vin = currentVinFromPage();
        if (!vin) { setStatus("APOS: VIN на странице не найден"); return; }
        const ops = parseAposText(text);
        if (!ops.length) { setStatus("APOS: операций не распознано"); return; }
        const res = await insertAposOperations(vin, ops, text);
        setStatus(res.skipped_duplicate ? `APOS ${vin}: уже собран ранее, дублей не льём`
                                        : `APOS ${vin}: вставлено операций ${res.count}`);
        return;
      }

      setStatus("страница не распознана (не поиск и не APOS)");
    } catch (e) {
      console.error("[vna] scan error", e);
      setStatus("ошибка: " + (e?.message || e));
    } finally { scanning = false; }
  }

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  /* ------------------------------- Статус-плашка -------------------------- */

  let badge = null;
  function setStatus(msg) {
    if (!badge) {
      badge = document.createElement("div");
      badge.id = "vna-badge";
      badge.style.cssText =
        "position:fixed;bottom:12px;right:12px;z-index:2147483646;max-width:340px;" +
        "background:#0b1220ee;color:#e6edf7;border:1px solid #2b3a55;border-radius:10px;" +
        "padding:8px 12px;font:12px/1.35 system-ui,Arial,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.45)";
      document.body.appendChild(badge);
    }
    badge.textContent = "VIN Normy Agent · " + msg;
  }

  /* --------------------------------- Init --------------------------------- */

  loadToken();
  GM_registerMenuCommand("⚙ Настроить Supabase (логин/пароль)", openSettings);
  GM_registerMenuCommand("▶ Собрать текущую страницу (поиск/APOS)", scan);
  GM_registerMenuCommand("⟳ Перелогиниться", () => login(true).then(ok => setStatus(ok ? "перелогин ок" : "перелогин фейл")));

  window.addEventListener("load", () => {
    if (CFG.url && CFG.anon && CFG.email && CFG.pass) {
      login(false).then(ok => { if (ok) scan(); });
    } else {
      setStatus("не настроен — открой меню расширения → ⚙ Настроить Supabase");
    }
  });
})();