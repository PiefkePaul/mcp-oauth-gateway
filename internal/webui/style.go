// Package webui holds the shared, dependency-free design system (CSS and small
// JS helpers) used by every server-rendered surface of the gateway: the public
// catalog, the account portal, the OAuth authorize/login pages and the admin
// console. Keeping it in one package means all three UIs stay visually and
// behaviorally consistent instead of drifting, and it ships as part of the
// single gateway binary -- no build step, no CDN dependency, no extra
// container.
package webui

// Style is the complete stylesheet, already wrapped in a <style> tag so
// callers can splice it straight into a template's <head>. It defines the
// full design-token system (light palette on :root, dark palette under
// prefers-color-scheme) plus every shared component class used across the
// public, account and admin templates.
const Style = `<style>
  :root {
    color-scheme: light;
    --bg: #eef1ef;
    --bg-dim: #e4e8e4;
    --surface: #ffffff;
    --surface-2: #f5f7f5;
    --ink: #182126;
    --muted: #5c6a67;
    --faint: #8a9793;
    --line: #dae1dd;
    --line-strong: #c3ccc6;
    --accent: #a86a17;
    --accent-strong: #8f5710;
    --accent-ink: #1b140a;
    --accent-soft: #f4e6cd;
    --info: #1b5e52;
    --info-soft: #dfeae6;
    --success: #1e7a52;
    --success-soft: #dff0e5;
    --warning: #946200;
    --warning-soft: #f7e9cf;
    --danger: #ae3b2e;
    --danger-soft: #f8e0dc;
    --shadow: 0 1px 2px rgba(24,33,38,0.04), 0 10px 28px rgba(24,33,38,0.07);
    --shadow-lift: 0 4px 10px rgba(24,33,38,0.06), 0 20px 46px rgba(24,33,38,0.12);
    --radius: 12px;
    --radius-sm: 8px;
    --font-ui: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
    --font-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --bg: #151b19;
      --bg-dim: #101513;
      --surface: #1e2622;
      --surface-2: #232c27;
      --ink: #eaeeea;
      --muted: #9aa8a2;
      --faint: #6c7a75;
      --line: #313b35;
      --line-strong: #3e4b43;
      --accent: #d9a24b;
      --accent-strong: #e8b968;
      --accent-ink: #211505;
      --accent-soft: #3a2c15;
      --info: #5ba996;
      --info-soft: #1d332e;
      --success: #4bab80;
      --success-soft: #1c3529;
      --warning: #d9a83e;
      --warning-soft: #3a2f14;
      --danger: #e27b6a;
      --danger-soft: #3a201c;
      --shadow: 0 1px 2px rgba(0,0,0,0.3), 0 10px 28px rgba(0,0,0,0.35);
      --shadow-lift: 0 4px 10px rgba(0,0,0,0.35), 0 24px 50px rgba(0,0,0,0.45);
    }
  }

  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font-family: var(--font-ui);
    font-size: 14.5px;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }
  h1, h2, h3, h4 { margin: 0; letter-spacing: -0.01em; font-weight: 600; }
  p { margin: 0; }
  a { color: var(--info); text-underline-offset: 2px; }
  code, .mono { font-family: var(--font-mono); }
  ::selection { background: var(--accent-soft); }
  button { font-family: inherit; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  hr { border: 0; border-top: 1px solid var(--line); margin: 0; }

  .muted, .hint { color: var(--faint); font-size: .84rem; }
  .stack { display: grid; gap: 1rem; }
  .stack-sm { display: grid; gap: .5rem; }
  .cluster { display: flex; flex-wrap: wrap; align-items: center; gap: .55rem; }
  .divider { height: 1px; background: var(--line); margin: 1.2rem 0; border: 0; }

  /* ---------- buttons / pills ---------- */
  .btn {
    appearance: none; border: 1px solid var(--line-strong); background: var(--surface);
    color: var(--ink); font: inherit; font-size: .86rem; font-weight: 600;
    padding: .6rem .95rem; border-radius: var(--radius-sm); cursor: pointer;
    display: inline-flex; align-items: center; gap: .45rem; text-decoration: none;
    line-height: 1;
  }
  .btn:hover { border-color: var(--faint); }
  .btn-primary { background: var(--accent); border-color: var(--accent-strong); color: var(--accent-ink); }
  .btn-primary:hover { background: var(--accent-strong); }
  .btn-ghost { background: transparent; border-color: transparent; }
  .btn-ghost:hover { background: var(--surface-2); border-color: transparent; }
  .btn-danger { color: var(--danger); }
  .btn-sm { padding: .42rem .68rem; font-size: .78rem; }
  form { margin: 0; }

  .pill {
    display: inline-flex; align-items: center; gap: .35rem;
    font-size: .74rem; font-weight: 600; padding: .22rem .55rem .22rem .5rem;
    border-radius: 999px; white-space: nowrap; line-height: 1.3;
  }
  .pill::before { content: ""; width: .4rem; height: .4rem; border-radius: 999px; background: currentColor; flex: none; }
  .pill-success { background: var(--success-soft); color: var(--success); }
  .pill-warning { background: var(--warning-soft); color: var(--warning); }
  .pill-danger  { background: var(--danger-soft); color: var(--danger); }
  .pill-info    { background: var(--info-soft); color: var(--info); }
  .pill-neutral { background: var(--surface-2); color: var(--muted); border: 1px solid var(--line); }

  /* ---------- forms ---------- */
  label, .field-label { display: block; font-size: .76rem; font-weight: 600; color: var(--muted); margin-bottom: .32rem; }
  input, select, textarea {
    width: 100%; font: inherit; font-size: .88rem; color: var(--ink);
    background: var(--surface); border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
    padding: .6rem .7rem;
  }
  input:focus, select:focus, textarea:focus { border-color: var(--accent); }
  input[type="checkbox"] { width: auto; }
  textarea { min-height: 5.4rem; resize: vertical; font-family: var(--font-mono); font-size: .84rem; }
  .field { display: grid; gap: .3rem; margin-top: .85rem; }
  .field:first-child { margin-top: 0; }
  .field-grid { display: grid; gap: .8rem; grid-template-columns: repeat(2, minmax(0,1fr)); }
  .field-grid .full { grid-column: 1 / -1; }
  .fieldset-title {
    font-size: .74rem; font-weight: 700; color: var(--muted); text-transform: uppercase;
    letter-spacing: .05em; margin: 1.1rem 0 .1rem;
  }
  .checkbox-row {
    display: flex; gap: .6rem; align-items: flex-start;
    border: 1px dashed var(--line-strong); border-radius: var(--radius-sm);
    padding: .75rem .85rem; background: var(--surface-2); margin-top: .85rem;
  }
  .checkbox-row input { margin-top: .2rem; }
  .checkbox-row label { margin: 0; font-weight: 600; color: var(--ink); font-size: .86rem; }
  .form-actions { display: flex; gap: .55rem; flex-wrap: wrap; margin-top: 1.1rem; }

  /* dynamic transport / source groups: shown or hidden by inline JS depending
     on a sibling <select>; the border marks them as a dependent sub-section */
  .dyn-group { display: grid; gap: 0; border-left: 2px solid var(--line-strong); padding-left: .9rem; margin: .9rem 0 0 .1rem; }
  .dyn-group[hidden] { display: none; }

  details { border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); padding: .85rem 1rem; }
  details + details { margin-top: .7rem; }
  details summary { cursor: pointer; font-weight: 700; font-size: .88rem; }
  details[open] summary { margin-bottom: .7rem; }

  /* ---------- tables ---------- */
  table { width: 100%; border-collapse: collapse; font-size: .86rem; }
  thead th {
    text-align: left; font-size: .72rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--faint); font-weight: 600; padding: 0 .7rem .55rem;
    border-bottom: 1px solid var(--line-strong);
  }
  tbody td { padding: .75rem .7rem; border-bottom: 1px solid var(--line); vertical-align: middle; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--surface-2); }
  .table-card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow); }
  .table-card table { font-size: .86rem; }
  .row-title { font-weight: 600; }
  .row-sub { color: var(--faint); font-size: .8rem; margin-top: .1rem; }

  /* ---------- callouts / notices ---------- */
  .callout { display: flex; gap: .6rem; padding: .8rem .9rem; border-radius: var(--radius-sm); border: 1px solid var(--line); background: var(--surface-2); font-size: .86rem; }
  .callout.success { background: var(--success-soft); border-color: transparent; color: var(--success); }
  .callout.danger { background: var(--danger-soft); border-color: transparent; color: var(--danger); }
  .callout.warning { background: var(--warning-soft); border-color: transparent; color: var(--warning); }

  /* ---------- shared shell pieces ---------- */
  .wordmark { display: flex; align-items: center; gap: .5rem; font-weight: 700; font-size: 1.02rem; letter-spacing: -0.01em; text-decoration: none; color: inherit; }
  .wordmark .mark { width: 1.55rem; height: 1.55rem; border-radius: 6px; background: var(--ink); color: var(--bg); display: grid; place-items: center; font-family: var(--font-mono); font-size: .78rem; font-weight: 600; flex: none; }

  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .95rem 1.4rem; border-bottom: 1px solid var(--line); background: var(--surface); }
  .topbar nav { display: flex; align-items: center; gap: .3rem; flex-wrap: wrap; }
  .topbar .navlink { font-size: .84rem; font-weight: 600; color: var(--muted); text-decoration: none; padding: .4rem .65rem; border-radius: 999px; }
  .topbar .navlink:hover { background: var(--surface-2); color: var(--ink); }
  .topbar .navlink.is-active { background: var(--surface-2); color: var(--ink); }

  .page { max-width: 76rem; margin: 0 auto; padding: 2.2rem 1.4rem 4rem; }
  .page-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.4rem; }
  .page-head h1 { font-size: clamp(1.5rem, 3vw, 1.9rem); }
  .eyebrow { display: inline-flex; align-items: center; gap: .4rem; font-family: var(--font-mono); font-size: .74rem; color: var(--info); background: var(--info-soft); padding: .28rem .6rem; border-radius: 999px; font-weight: 600; margin-bottom: .7rem; }

  .catalog { display: grid; grid-template-columns: repeat(auto-fill, minmax(19rem,1fr)); gap: 1rem; }
  .route-card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 1.05rem; display: grid; gap: .7rem; box-shadow: var(--shadow); }
  .route-card:hover { box-shadow: var(--shadow-lift); border-color: var(--line-strong); }
  .route-card h3 { font-size: .98rem; }
  .route-card .path { font-family: var(--font-mono); font-size: .78rem; color: var(--faint); }
  .kv-mini { display: grid; gap: .3rem; font-size: .78rem; }
  .kv-mini .k { color: var(--faint); }

  .panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }
  .panel-head { padding: 1rem 1.1rem; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
  .panel-head h2, .panel-head h3 { font-size: .98rem; }
  .panel-body { padding: 1.1rem; }

  .stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem,1fr)); gap: .8rem; }
  .stat-tile { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: .9rem 1rem; }
  .stat-tile .label { font-size: .72rem; color: var(--faint); text-transform: uppercase; letter-spacing: .05em; font-weight: 600; }
  .stat-tile .value { font-family: var(--font-mono); font-size: 1.4rem; margin-top: .25rem; font-weight: 600; word-break: break-all; }

  .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .searchbox { display: flex; align-items: center; gap: .4rem; border: 1px solid var(--line-strong); background: var(--surface); border-radius: var(--radius-sm); padding: .4rem .6rem; font-size: .82rem; color: var(--faint); min-width: 14rem; }

  .tabs { display: flex; gap: .4rem; flex-wrap: wrap; margin: 1.2rem 0 1.4rem; border-bottom: 1px solid var(--line); }
  .tab { padding: .6rem .2rem; margin-right: 1.2rem; color: var(--muted); text-decoration: none; font-weight: 600; font-size: .9rem; border-bottom: 2px solid transparent; }
  .tab:hover { color: var(--ink); }
  .tab.active { color: var(--ink); border-bottom-color: var(--accent); }

  /* ---------- admin shell ---------- */
  .admin-shell { display: grid; grid-template-columns: 15rem 1fr; min-height: 100vh; }
  .admin-rail { background: var(--surface); border-right: 1px solid var(--line); padding: 1.1rem .8rem; display: flex; flex-direction: column; gap: 1.3rem; }
  .admin-rail .wordmark { padding: 0 .5rem .6rem; }
  .rail-group { display: grid; gap: .1rem; }
  .rail-group .rail-title { font-size: .68rem; text-transform: uppercase; letter-spacing: .07em; color: var(--faint); font-weight: 700; padding: .3rem .5rem; }
  .rail-link {
    display: flex; align-items: center; gap: .6rem; padding: .5rem .5rem; border-radius: var(--radius-sm);
    color: var(--muted); text-decoration: none; font-size: .86rem; font-weight: 600;
  }
  .rail-link:hover { background: var(--surface-2); color: var(--ink); }
  .rail-link.is-active { background: var(--accent-soft); color: var(--accent-strong); }
  .rail-foot { margin-top: auto; padding: .6rem .5rem; font-size: .76rem; color: var(--faint); border-top: 1px solid var(--line); }
  .admin-main { min-width: 0; }
  .admin-topbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .95rem 1.6rem; border-bottom: 1px solid var(--line); background: var(--surface); flex-wrap: wrap; }
  .breadcrumb { font-size: .82rem; color: var(--faint); display: flex; gap: .4rem; align-items: center; }
  .breadcrumb strong { color: var(--ink); font-weight: 600; }
  .admin-content { padding: 1.6rem; display: grid; gap: 1.4rem; max-width: 96rem; }
  .split { display: grid; grid-template-columns: 1.3fr 1fr; gap: 1.4rem; align-items: start; }

  /* ---------- auth shell (login/register) ---------- */
  .auth-shell { min-height: 100vh; display: grid; grid-template-columns: 1fr 1fr; }
  .auth-side { background: var(--ink); color: var(--bg); padding: 2.6rem; display: flex; flex-direction: column; justify-content: space-between; }
  .auth-side .wordmark { color: var(--bg); }
  .auth-side .wordmark .mark { background: var(--accent); color: var(--accent-ink); }
  .auth-side blockquote { font-size: 1.25rem; line-height: 1.35; max-width: 26ch; letter-spacing: -0.01em; font-weight: 500; margin: 0; }
  .auth-side .foot { font-family: var(--font-mono); font-size: .78rem; opacity: .6; }
  .auth-main { display: flex; align-items: center; justify-content: center; padding: 2.4rem; }
  .auth-card { width: 100%; max-width: 23rem; display: grid; gap: 1.2rem; }
  .auth-card h1 { font-size: 1.4rem; }

  .empty { display: grid; place-items: center; gap: .5rem; padding: 3rem 1rem; text-align: center; color: var(--faint); }

  /* ---------- catalog: one full-width row per server ---------- */
  .catalog-list { display: grid; gap: .7rem; }
  .route-row-card {
    background: var(--surface); border: 1px solid var(--line); border-radius: 999px;
    padding: .7rem .8rem .7rem 1.2rem; box-shadow: var(--shadow);
    display: grid; grid-template-columns: 13rem 1fr 11rem auto auto; gap: 1.2rem; align-items: center;
  }
  .route-row-card:hover { box-shadow: var(--shadow-lift); border-color: var(--line-strong); }
  .rrc-id h3 { font-size: .94rem; }
  .rrc-id .path { font-family: var(--font-mono); font-size: .76rem; color: var(--faint); margin-top: .1rem; }
  .rrc-desc { font-size: .84rem; color: var(--muted); }
  .rrc-meta { display: flex; align-items: baseline; gap: .4rem; font-size: .78rem; min-width: 0; text-align: left; }
  .rrc-meta .k { color: var(--faint); flex: none; }
  .rrc-meta .tt { position: relative; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: default; }
  .rrc-meta .tt::after {
    content: attr(data-full); position: absolute; left: 0; top: calc(100% + .4rem); z-index: 20;
    background: var(--ink); color: var(--bg); font-family: var(--font-mono); font-size: .74rem;
    padding: .35rem .55rem; border-radius: 6px; white-space: nowrap; box-shadow: var(--shadow-lift);
    opacity: 0; pointer-events: none; transform: translateY(-2px); transition: opacity .1s, transform .1s;
  }
  .rrc-meta .tt:hover::after { opacity: 1; transform: translateY(0); }
  .rrc-actions { display: flex; gap: .4rem; }

  /* ---------- admin routes: browse-all vs. compact-list + centered editor ---------- */
  .editor-shell { display: grid; grid-template-columns: 15rem 1fr; gap: 1.2rem; align-items: start; }
  .route-compact-list { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; position: sticky; top: 1rem; }
  .compact-list-head { display: flex; justify-content: space-between; gap: .4rem; padding: .7rem; border-bottom: 1px solid var(--line); }
  .compact-row {
    display: flex; align-items: center; gap: .5rem; padding: .65rem .7rem; cursor: pointer;
    border-bottom: 1px solid var(--line); font-size: .82rem; background: none; border-left: 0 solid transparent;
    width: 100%; text-align: left; color: var(--ink); font: inherit;
  }
  .compact-row:last-child { border-bottom: none; }
  .compact-row:hover { background: var(--surface-2); }
  .compact-row.is-active { background: var(--accent-soft); border-left: 3px solid var(--accent-strong); padding-left: calc(.7rem - 3px); }
  .compact-row .dot { width: .5rem; height: .5rem; border-radius: 999px; flex: none; background: var(--faint); }
  .compact-row.is-active .dot { background: var(--accent-strong); }
  .compact-row .name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .compact-row .chip { font-family: var(--font-mono); font-size: .66rem; color: var(--faint); flex: none; }
  .transport-chip {
    display: inline-block; font-family: var(--font-mono); font-size: .68rem; font-weight: 600;
    color: var(--info); background: var(--info-soft); padding: .04rem .4rem; border-radius: 4px; margin-left: .35rem;
  }

  .editor-center { display: flex; justify-content: center; }
  .editor-panel { width: 100%; max-width: 40rem; }
  .editor-panel .panel-body { padding: 1.6rem 1.8rem 1.8rem; }
  .editor-panel .panel-head { padding: 1.2rem 1.8rem; }

  .confirm-overlay {
    position: fixed; inset: 0; background: rgba(10,14,12,0.45); backdrop-filter: blur(2px);
    display: flex; align-items: center; justify-content: center; z-index: 100; padding: 1rem;
  }
  .confirm-overlay[hidden] { display: none; }
  .confirm-card {
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
    box-shadow: var(--shadow-lift); padding: 1.3rem 1.4rem; width: 100%; max-width: 24rem;
  }
  .confirm-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1.1rem; justify-content: flex-end; }

  /* ---------- build & stdio: choose which form to show ---------- */
  .build-chooser { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; }
  .build-choice {
    text-align: left; appearance: none; cursor: pointer; font: inherit;
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
    padding: 1rem 1.1rem; display: grid; gap: .35rem; box-shadow: var(--shadow);
  }
  .build-choice:hover { border-color: var(--line-strong); }
  .build-choice.is-active { border-color: var(--accent); background: var(--accent-soft); box-shadow: none; }
  .build-choice-title { font-weight: 700; font-size: .92rem; }
  .build-choice.is-active .build-choice-title { color: var(--accent-strong); }
  .build-choice-desc { font-size: .8rem; color: var(--muted); }

  @media (max-width: 980px) {
    .auth-shell { grid-template-columns: 1fr; }
    .auth-side { display: none; }
    .admin-shell { grid-template-columns: 1fr; }
    .admin-rail { display: none; }
    .split { grid-template-columns: 1fr; }
    .field-grid { grid-template-columns: 1fr; }
    .route-row-card { grid-template-columns: 1fr; border-radius: var(--radius); gap: .5rem; text-align: left; padding: .9rem 1rem; }
    .rrc-actions { justify-content: flex-start; }
    .rrc-meta .tt { overflow: visible; white-space: normal; }
    .editor-shell { grid-template-columns: 1fr; }
    .route-compact-list { position: static; }
    .build-chooser { grid-template-columns: 1fr; }
  }
</style>`

// GoogleFonts links the IBM Plex family used throughout the design system.
// Production deployments that must not depend on an external CDN (air-gapped
// or privacy-sensitive networks) can swap this constant for a self-hosted
// @font-face block backed by files embedded via go:embed -- every template
// only references the font by name, so no other change is required.
const GoogleFonts = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">`

// DynGroupScript wires up a <select> that toggles a set of sibling
// "[data-dyn-group]" sections, showing only the ones whose data-dyn-group
// value (a single value, or several separated by spaces when a field
// applies to more than one choice) contains the select's current value. It
// is the client-side half of "show only the settings that actually apply to
// the current choice" used by the route transport selector (some fields,
// like Forward Headers, are valid for more than one transport) and the
// STDIO-install / image-build source pickers. Call wireDynGroup('select-id')
// once per <select> after the DOM for that form has rendered.
const DynGroupScript = `<script>
  function wireDynGroup(selectId) {
    var select = document.getElementById(selectId);
    if (!select) return;
    var scope = select.closest('form') || document;
    var groups = scope.querySelectorAll('[data-dyn-group]');
    var hints = scope.querySelectorAll('[data-dyn-hint]');
    function matches(el, attr, mode) {
      var raw = el.getAttribute(attr) || '';
      return raw.split(/\s+/).indexOf(mode) !== -1;
    }
    function apply() {
      var mode = select.value;
      groups.forEach(function (g) { g.hidden = !matches(g, 'data-dyn-group', mode); });
      hints.forEach(function (h) { h.hidden = !matches(h, 'data-dyn-hint', mode); });
    }
    select.addEventListener('change', apply);
    apply();
  }
</script>`
