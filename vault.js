/* خزنة التوكين لصفحة إدارة المستخدمين.
   التوكين بيتشفّر بـ AES-GCM بمفتاح مشتق من (اسم المستخدم + الباسورد) عبر PBKDF2،
   والمفتاح مش موجود في الصفحة. بيتفك في الذاكرة بس عند الدخول. */
(() => {
  "use strict";
  const STORE = "si_vault_v1";
  const PREFIX = "SIV1.";
  const ITER = 600000;
  const IDLE_MS = 15 * 60 * 1000;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const AAD = enc.encode("SI-VAULT-1");
  const q = (id) => document.getElementById(id);
  let mode = "login";
  let idleTimer = null;

  // ---------- تشفير ----------
  const b64 = (u8) => {
    let s = "";
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKey(user, pass, salt, iterations) {
    const base = await crypto.subtle.importKey(
      "raw", enc.encode(user.trim().toLowerCase() + "\u0000" + pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function seal(user, pass, payload) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(user, pass, salt, ITER);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: AAD }, key, enc.encode(JSON.stringify(payload))));
    return { v: 1, it: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  }
  async function open(vault, user, pass) {
    try {
      const key = await deriveKey(user, pass, unb64(vault.salt), vault.it);
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: unb64(vault.iv), additionalData: AAD }, key, unb64(vault.ct));
      const data = JSON.parse(dec.decode(pt));
      return data && typeof data.login === "string" && typeof data.token === "string" ? data : null;
    } catch { return null; }
  }

  // ---------- تخزين ورقم التسجيل ----------
  function readVault() {
    try { const raw = localStorage.getItem(STORE); return raw ? JSON.parse(raw) : null; }
    catch { return null; }
  }
  function saveVault(v) {
    try { localStorage.setItem(STORE, JSON.stringify(v)); return true; } catch { return false; }
  }
  const vaultCode = (v) => PREFIX + btoa(JSON.stringify(v));
  function parseCode(text) {
    try {
      const t = String(text).replace(/\s/g, "");
      if (!t.startsWith(PREFIX)) return null;
      const v = JSON.parse(atob(t.slice(PREFIX.length)));
      const ok = v && v.v === 1 && Number.isInteger(v.it) && v.it >= 100000 && v.it <= 2000000 &&
        ["salt", "iv", "ct"].every((k) => typeof v[k] === "string" && v[k].length < 4096);
      return ok ? { v: 1, it: v.it, salt: v.salt, iv: v.iv, ct: v.ct } : null;
    } catch { return null; }
  }

  // ---------- GitHub ----------
  const gh = (path, token) => fetch("https://api.github.com" + path, {
    cache: "no-store",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: "Bearer " + token,
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });

  async function connect(login, token) {
    await request("/api/login", { method: "POST", body: JSON.stringify({ username: login, password: token }) });
    await loadUsers();
    if (githubToken) afterLogin();
  }

  async function loadTokenInfo() {
    let el = q("token-info");
    if (!el) {
      el = document.createElement("div");
      el.id = "token-info";
      el.className = "footer-note";
      q("storage-note").after(el);
    }
    el.textContent = "جارٍ فحص صلاحيات التوكين...";
    try {
      const r = await gh(`/repos/${githubOwner}/${githubRepo}`, githubToken);
      const j = await r.json();
      let txt = "صلاحية التوكين: ";
      if (j && typeof j.permissions === "object" && j.permissions) {
        txt += j.permissions.push ? "قراءة وكتابة" : "قراءة فقط (التعديلات لن تُحفظ)";
      } else txt += "غير محددة";
      const exp = r.headers.get("github-authentication-token-expiration");
      const d = exp ? new Date(exp.replace(" ", "T").replace(" UTC", "Z")) : null;
      if (d && !isNaN(d)) {
        const days = Math.ceil((d - Date.now()) / 86400000);
        txt += ` · ينتهي بعد ${days} يوم (${d.toISOString().slice(0, 10)})`;
        if (days <= 7) txt += " ⚠ جدّده قريباً";
      } else txt += " · تاريخ الانتهاء غير متاح من المتصفح";
      el.textContent = txt;
    } catch { el.textContent = "تعذّر فحص صلاحيات التوكين."; }
  }

  // ---------- بعد الدخول: زر رقم التسجيل + قفل الخمول ----------
  const codeBtn = document.createElement("button");
  codeBtn.id = "vault-code-button";
  codeBtn.className = "button logout";
  codeBtn.type = "button";
  codeBtn.hidden = true;
  codeBtn.textContent = "رقم التسجيل";
  document.querySelector("header .toolbar").prepend(codeBtn);
  codeBtn.addEventListener("click", () => {
    const v = readVault();
    if (v) showCode(v);
    else showError("مفيش خزنة محفوظة على الجهاز ده.");
  });

  function afterLogin() {
    codeBtn.hidden = false;
    armIdle();
    loadTokenInfo();
  }
  function armIdle() {
    clearTimeout(idleTimer);
    if (githubToken) idleTimer = setTimeout(lock, IDLE_MS);
  }
  async function lock() {
    if (!githubToken) return;
    await request("/api/logout", { method: "POST", body: "{}" });
    closeDialog();
    showLogin();
    codeBtn.hidden = true;
    renderPanel();
    showError("اتقفلت الجلسة بسبب الخمول. أدخل الباسورد للمتابعة.");
  }
  ["pointerdown", "keydown", "scroll"].forEach((ev) =>
    document.addEventListener(ev, armIdle, { passive: true }));
  q("logout-button").addEventListener("click", () => {
    clearTimeout(idleTimer);
    codeBtn.hidden = true;
    renderPanel();
  });

  function showCode(vault) {
    const box = document.createElement("div");
    const title = document.createElement("h2");
    title.id = "dialog-title";
    title.textContent = "رقم التسجيل";
    const note = document.createElement("p");
    note.className = "password-note";
    note.textContent = "ده التوكين مشفّر بالباسورد بتاعك. استخدمه لو عايز تدخل من جهاز تاني (استيراد رقم تسجيل). " +
      "من غير الباسورد مالوش فايدة، بس ما تشاركوش مع حد وخلّي الباسورد قوي.";
    const area = document.createElement("textarea");
    area.readOnly = true;
    area.rows = 5;
    area.dir = "ltr";
    area.value = vaultCode(vault);
    Object.assign(area.style, {
      width: "100%", margin: "12px 0", padding: "10px", border: "1px solid var(--line)",
      borderRadius: "9px", fontFamily: "Consolas, monospace", fontSize: "12px"
    });
    const actions = document.createElement("div");
    actions.className = "form-actions";
    const copy = document.createElement("button");
    copy.className = "button";
    copy.type = "button";
    copy.textContent = "نسخ";
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(area.value); copy.textContent = "تم النسخ"; }
      catch { area.select(); }
    });
    const done = document.createElement("button");
    done.className = "button secondary";
    done.type = "button";
    done.textContent = "تم";
    done.addEventListener("click", closeDialog);
    actions.append(copy, done);
    box.append(title, note, area, actions);
    openDialog(box);
  }

  // ---------- شاشة الدخول ----------
  const field = (id, label, type, auto) =>
    `<div class="field full"><label for="${id}">${label}</label>` +
    `<input id="${id}" type="${type}" required autocomplete="${auto}" autocapitalize="none" spellcheck="false"></div>`;

  function renderPanel() {
    if (mode !== "import") mode = readVault() ? "login" : "setup";
    const t = {
      login: ["الدخول إلى لوحة الإدارة", "أدخل اسم المستخدم وكلمة المرور الخاصين بالخزنة.", "دخول"],
      setup: ["إنشاء خزنة التوكين (مرة واحدة)",
        "الصق التوكين مرة واحدة واختار اسم مستخدم وباسورد. التوكين بيتشفّر على جهازك بالباسورد، وبعدها هتدخل بيوزر وباسورد بس.",
        "إنشاء الخزنة والدخول"],
      import: ["استيراد رقم تسجيل", "الصق رقم التسجيل وأدخل اسم المستخدم والباسورد اللي اتعمل بيهم.", "استيراد ودخول"]
    }[mode];
    let fields = "";
    if (mode === "setup") {
      fields += field("v-token", "رمز GitHub (Fine-grained token)", "password", "off");
    }
    if (mode === "import") {
      fields += '<div class="field full"><label for="v-code">رقم التسجيل</label>' +
        '<textarea id="v-code" required rows="4" dir="ltr" spellcheck="false" ' +
        'style="width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:9px;font-family:Consolas,monospace;font-size:12px"></textarea></div>';
    }
    fields += field("v-user", "اسم المستخدم", "text", "username");
    fields += field("v-pass", "كلمة المرور", "password", mode === "setup" ? "new-password" : "current-password");
    if (mode === "setup") fields += field("v-pass2", "تأكيد كلمة المرور", "password", "new-password");
    const hint = mode === "setup"
      ? '<span class="hint">اعمل التوكين للمستودع SmartInventory-Users بس (مش SmartInventory-Users-Admin)، بصلاحية Contents: Read and write، وله تاريخ انتهاء. الباسورد 12 حرف أو أكتر ومفيش طريقة لاسترجاعه لو اتنسي. ' +
        '<a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener noreferrer">إنشاء رمز GitHub</a></span>'
      : "";
    const links = {
      login: '<button id="v-link" class="button secondary" type="button">إعادة ضبط الخزنة</button>',
      setup: '<button id="v-link" class="button secondary" type="button">عندي رقم تسجيل</button>',
      import: '<button id="v-link" class="button secondary" type="button">رجوع</button>'
    }[mode];
    q("login-panel").innerHTML =
      `<h2>${t[0]}</h2><p>${t[1]}</p><form id="v-form" autocomplete="off"><div class="form-grid">${fields}</div>${hint}` +
      `<div class="form-actions"><button id="v-submit" class="button" type="submit">${t[2]}</button>${links}</div></form>`;
    q("v-form").addEventListener("submit", onSubmit);
    q("v-link").addEventListener("click", () => {
      if (mode === "login") {
        if (!confirm("هيتمسح التوكين المشفّر من الجهاز ده وهتحتاج تدخل توكين جديد. متأكد؟")) return;
        try { localStorage.removeItem(STORE); } catch { /* ignore */ }
        mode = "setup";
      } else mode = mode === "setup" ? "import" : "login";
      clearError();
      renderPanel();
    });
  }

  async function onSubmit(event) {
    event.preventDefault();
    const submit = q("v-submit");
    submit.disabled = true;
    clearError();
    try {
      if (mode === "setup") await doSetup();
      else if (mode === "import") await doImport();
      else await doLogin();
    } catch (error) {
      let message = error.message || "حصل خطأ غير متوقع.";
      if (error.status === 401 && mode === "login") {
        message += " جدّد التوكين من GitHub ثم اضغط «إعادة ضبط الخزنة».";
      }
      showError(message);
    } finally {
      if (q("v-submit")) q("v-submit").disabled = false;
    }
  }

  async function doLogin() {
    const vault = readVault();
    if (!vault) throw new Error("مفيش خزنة على الجهاز ده.");
    const data = await open(vault, q("v-user").value, q("v-pass").value);
    if (!data) throw new Error("اسم المستخدم أو كلمة المرور غير صحيحة.");
    await connect(data.login, data.token);
  }

  async function doSetup() {
    const token = q("v-token").value.trim();
    const user = q("v-user").value.trim();
    const pass = q("v-pass").value;
    if (!/^[\x21-\x7e]{20,255}$/.test(token)) throw new Error("التوكين يبدو غير صالح.");
    if (user.length < 3) throw new Error("اسم المستخدم 3 أحرف على الأقل.");
    if (pass.length < 12) throw new Error("الباسورد 12 حرف على الأقل.");
    if (pass !== q("v-pass2").value) throw new Error("تأكيد الباسورد غير مطابق.");
    let response;
    try { response = await gh("/user", token); }
    catch { throw new Error("تعذّر الاتصال بـ GitHub. تحقق من الإنترنت."); }
    if (!response.ok) {
      const error = new Error(response.status === 401 ? "رمز GitHub غير صالح أو منتهي." : `تعذّر التحقق من الرمز (HTTP ${response.status}).`);
      throw error;
    }
    const login = (await response.json()).login;
    await connect(login, token);
    if (!githubToken) return;
    const vault = await seal(user, pass, { login, token });
    if (!saveVault(vault)) showError("اتسجّل الدخول، لكن المتصفح منع حفظ الخزنة. انسخ رقم التسجيل واحتفظ بيه.");
    renderPanel();
    showCode(vault);
  }

  async function doImport() {
    const vault = parseCode(q("v-code").value);
    if (!vault) throw new Error("رقم التسجيل غير صالح.");
    const data = await open(vault, q("v-user").value, q("v-pass").value);
    if (!data) throw new Error("اسم المستخدم أو كلمة المرور غير صحيحة.");
    if (!saveVault(vault)) throw new Error("المتصفح منع حفظ الخزنة.");
    mode = "login";
    await connect(data.login, data.token);
    renderPanel();
  }

  renderPanel();
})();
