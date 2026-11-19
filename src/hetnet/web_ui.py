"""Static, dependency-free responsive browser UI for the local HetNet simulator.

All dynamic content is rendered through textContent, never innerHTML.
The research view reads only curated synthetic summaries. Private key and
operator-data workflows intentionally remain command-line-only.
"""
HTML = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0b1221">
<title>HetNet Studio — исследовательский симулятор 2G–5G</title>
<style>
:root{color-scheme:dark;--bg:#0b1221;--panel:#121e32;--panel2:#172640;--border:#2a3c56;--text:#f0f5ff;--muted:#9baac5;--accent:#55d6bf;--blue:#86b7fa;--amber:#f5be72;--red:#fc9a9e;--radius:16px;font:14px/1.48 system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 77% -15%,#1c3659,transparent 41%),var(--bg);color:var(--text)}
button,input,select{font:inherit}button{cursor:pointer}button:disabled{opacity:.55;cursor:wait}
a{color:var(--accent)}:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
[hidden]{display:none!important}
.shell{min-height:100vh;display:grid;grid-template-columns:236px minmax(0,1fr)}
aside{background:#101a2b;border-right:1px solid var(--border);padding:26px 18px;display:flex;flex-direction:column;gap:27px}
.brand{display:flex;align-items:center;gap:13px;padding:2px 8px}.brand-icon{width:40px;height:40px;border:1px solid #378e8b;border-radius:12px;background:linear-gradient(135deg,#173d50,#174736);display:grid;place-items:center;color:var(--accent);font-size:25px}
.brand strong{display:block;font-size:21px;letter-spacing:-.8px}.brand small{display:block;color:var(--muted);font-size:11px;letter-spacing:.3px}
.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.6px;color:#8da1c4;margin:0 11px 7px}
.nav-btn{display:flex;align-items:center;gap:12px;width:100%;border:1px solid transparent;text-align:left;padding:12px;border-radius:11px;color:#bdcce4;background:transparent}
.nav-btn:hover{background:#1a2940}.nav-btn[aria-current="page"]{background:#20394b;color:var(--accent);border-color:#315e62}
.nav-icon{font-size:18px;width:23px;text-align:center}.side-bottom{margin-top:auto;border-top:1px solid var(--border);padding:22px 9px 0;color:var(--muted);font-size:12px}
.side-bottom strong{color:var(--text);display:block;margin-bottom:4px}.chip{display:inline-block;border:1px solid #33645f;background:#1a3939;color:#a2f3da;border-radius:30px;padding:3px 10px;font-size:11px;font-weight:650;letter-spacing:.15px}
main{min-width:0;padding:27px clamp(18px,3vw,42px) 55px;max-width:1740px;width:100%;margin:auto}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:25px}
.eyebrow{font-size:11px;color:var(--accent);font-weight:750;text-transform:uppercase;letter-spacing:1.6px;margin:0 0 7px}
h1{font-size:clamp(24px,3vw,35px);line-height:1.14;letter-spacing:-1px;margin:0}
h2{font-size:18px;margin:0;font-weight:700;letter-spacing:-.3px}h3{font-size:14px;margin:0 0 6px}
.subtitle{color:var(--muted);margin:9px 0 0;max-width:780px}
.head-meta{white-space:nowrap;color:#acc1dc;font-size:12px;border:1px solid var(--border);padding:8px 12px;border-radius:9px;background:#142238}
.card{background:linear-gradient(155deg,var(--panel),#121d30);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 8px 22px #07102020}
.card-inner{padding:20px}.card-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:14px}
.muted{color:var(--muted)}.small{font-size:12px}.hint{font-size:11px;color:var(--muted)}
.grid2{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(290px,1fr);gap:16px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:16px 0}
.stat{padding:19px}.stat .value{font-size:clamp(22px,2.4vw,31px);font-weight:780;letter-spacing:-1px;display:block;margin-top:6px}.stat .label{font-size:12px;color:var(--muted)}
.section-gap{margin-top:16px}.form-grid{display:grid;grid-template-columns:repeat(6,minmax(115px,1fr));gap:12px}
.field{display:flex;flex-direction:column;gap:6px;min-width:0}.field span{font-size:12px;color:#b8c8e2}
.field input,.field select,.filter{width:100%;min-width:0;border:1px solid #39506a;color:var(--text);background:#0c1728;border-radius:9px;padding:10px 11px}
.field select{appearance:auto}.field input:focus,.field select:focus,.filter:focus{border-color:var(--accent)}
.field.wide{grid-column:span 2}.form-bottom{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:16px}
.primary{border:none;border-radius:9px;color:#092422;background:linear-gradient(130deg,#72e3d0,#45c5bd);font-weight:790;padding:11px 18px;box-shadow:0 4px 16px #3bc7b61e}
.secondary{border:1px solid #42607a;border-radius:9px;background:#1a2b44;color:#d4e4fa;font-weight:650;padding:10px 14px}
.secondary:hover{border-color:#6a9aba}.preset{padding:7px 11px;border-radius:8px;font-size:12px;border:1px solid #344c68;background:#1b2a42;color:#b9cee8}
.preset:hover{color:#fff;background:#27435d}
.inline-status{font-size:12px;color:#98dcca;min-height:18px}.inline-status.error{color:var(--red)}
.divider{height:1px;background:var(--border);margin:16px 0}
.network-svg{width:100%;height:auto;display:block;min-height:340px}
.legend{display:flex;gap:11px;flex-wrap:wrap;color:#b7cae3;font-size:11px}
.legend span{display:inline-flex;align-items:center;gap:5px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:50%}
.scroll{max-height:360px;overflow:auto;scrollbar-color:#375573 transparent}
table{border-collapse:collapse;width:100%;font-size:12px;min-width:620px}
th{position:sticky;top:0;background:#16243a;color:#a9c0df;font-weight:650;text-align:left;z-index:1}
td,th{padding:11px 12px;border-bottom:1px solid #2b3d54}
tbody tr:hover{background:#1a2b44}.mono{font-variant-numeric:tabular-nums;font-family:ui-monospace,"SFMono-Regular",Consolas,monospace}
.pill{display:inline-flex;align-items:center;max-width:100%;padding:3px 9px;border-radius:15px;font-size:10px;font-weight:750;color:#abf1df;background:#1c4543}
.pill.warn{background:#4a372a;color:#f7c28c}.pill.bad{background:#4a2f3e;color:#ffacb4}.pill.neutral{background:#293c56;color:#bfd5f3}
.alert{border-left:3px solid #edab76;padding:12px 10px 12px 14px;border-bottom:1px solid #293951}
.alert strong{font-size:12px}.alert p{margin:5px 0;color:var(--muted);font-size:12px}
.mini-bars{display:flex;align-items:flex-end;gap:5px;height:130px;margin:10px 0 4px;border-bottom:1px solid #3b4c64}
.mini-bars div{flex:1;border-radius:5px 5px 0 0;min-height:3px;background:linear-gradient(#65dac7,#39768d);position:relative}
.mini-bars div:hover{filter:brightness(1.2)}.mini-bars div:focus-visible{outline:2px solid white}
.mini-bars div::after{content:attr(data-count);position:absolute;top:-20px;left:50%;transform:translateX(-50%);font-size:10px;color:#b5c8e5}
.toolbar{display:flex;gap:9px;flex-wrap:wrap;align-items:center}.toolbar .filter{width:auto;max-width:270px}
.list-empty{font-size:12px;color:var(--muted);padding:15px}.callout{color:#bcd2e8;background:#15293c;border:1px solid #2b4b60;border-radius:11px;padding:12px 15px;font-size:12px}
.bar-row{display:grid;grid-template-columns:minmax(125px,1fr) minmax(100px,2fr) 62px;gap:15px;align-items:center;padding:15px 0;border-bottom:1px solid var(--border)}
.bar-track{background:#20344d;height:12px;border-radius:30px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#318c9d,#5bdfbe);border-radius:30px;transition:width .25s ease}
.result-tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:17px 0}.result-tile{background:#172840;border:1px solid #2a405e;border-radius:11px;padding:14px}.result-tile b{font-size:19px;display:block}
.study-summary{display:grid;grid-template-columns:1fr 1fr;gap:16px}
code{background:#182d45;color:#9ee7d4;padding:2px 5px;border-radius:4px}.code-box{background:#091523;color:#bddde4;border:1px solid #2b4457;border-radius:9px;padding:14px;overflow:auto;font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word}
.step{display:flex;gap:12px;padding:14px 0;border-bottom:1px solid var(--border)}.step-index{width:30px;height:30px;flex-shrink:0;display:grid;place-items:center;border-radius:50%;background:#1e4149;color:var(--accent);font-weight:800}
.footer-note{font-size:11px;color:#899ebc;margin-top:23px}
@media(max-width:1170px){.form-grid{grid-template-columns:repeat(3,minmax(130px,1fr))}.stats{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}}
@media(max-width:780px){.shell{display:block}aside{position:relative;padding:11px 14px;gap:8px}.brand{display:none}.nav-label,.side-bottom{display:none}.nav-links{display:flex;gap:6px;overflow:auto}.nav-btn{white-space:nowrap;padding:9px 12px}.nav-icon{display:none}main{padding:20px 13px 40px}.topbar{flex-wrap:wrap}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.field.wide{grid-column:span 2}.study-summary{grid-template-columns:1fr}.result-tiles{grid-template-columns:repeat(2,1fr)}.toolbar .filter{max-width:100%}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body><div class="shell">
<aside aria-label="Навигация">
  <div class="brand"><div class="brand-icon" aria-hidden="true">⌁</div><div><strong>HetNet</strong><small>RESEARCH STUDIO</small></div></div>
  <div><div class="nav-label">Рабочее пространство</div><nav class="nav-links" aria-label="Разделы">
  <button type="button" class="nav-btn" data-view="overview" aria-current="page"><span class="nav-icon">▦</span>Обзор сети</button>
  <button type="button" class="nav-btn" data-view="research"><span class="nav-icon">◉</span>Исследования</button>
  <button type="button" class="nav-btn" data-view="security"><span class="nav-icon">◇</span>Доверие и защита</button>
  </nav></div>
  <div class="side-bottom"><strong>Лабораторный режим</strong>Только синтетические сценарии. Нет подключения к действующим сетям или данным абонентов.</div>
</aside>
<main>
  <header class="topbar"><div><div class="eyebrow">CONTROL PLANE / 2G · 3G · 4G · IMS · 5G</div>
  <h1 id="page-title">Обзор гетерогенной сети</h1><p class="subtitle" id="page-subtitle">Интерактивная модель сигнализации, узлового контроля КИЕ и наблюдателей. Все данные синтетические.</p></div>
  <span class="head-meta"><span class="chip">● LOCAL SIMULATION</span> &nbsp; HetNet Studio</span></header>
  <section id="overview">
    <div class="card card-inner">
      <div class="card-head"><div><h2>Параметры моделирования</h2><div class="small muted">Выберите профиль или измените условия вручную</div></div>
      <div class="toolbar"><button type="button" class="preset" data-preset="normal">Штатная сеть</button><button type="button" class="preset" data-preset="fault">Подделка КИЕ</button><button type="button" class="preset" data-preset="outage">Потеря кворума</button></div></div>
      <form id="controls"><div class="form-grid">
        <label class="field"><span>Длительность, с</span><input id="duration" type="number" min="5" max="90" step="1" value="18" required></label>
        <label class="field"><span>Абоненты</span><input id="subscribers" type="number" min="4" max="40" step="1" value="8" required></label>
        <label class="field"><span>Seed</span><input id="seed" type="number" min="0" max="999999999" step="1" value="42" required></label>
        <label class="field"><span>Трафик, ×</span><input id="traffic" type="number" min="0" max="10" step=".5" value="1" required></label>
        <label class="field"><span>Сценарий КИЕ</span><select id="nodecase"><option value="auto">Автоматически</option><option value="none">Норма</option><option value="report">Ложный отчёт</option><option value="tamper">Подмена на маршруте</option><option value="both">Оба сценария</option></select></label>
        <label class="field"><span>Наблюдатели</span><select id="observercase"><option value="none">3 исправны</option><option value="one_faulty">1 неисправен</option><option value="two_colluding">2 в сговоре</option><option value="outage">Нет кворума</option><option value="mixed">Смешанный сбой</option><option value="bad_mac">Неверный MAC</option><option value="stale">Устаревший отчёт</option></select></label>
        <label class="field"><span>Потеря голосов, %</span><input id="observerloss" type="number" min="0" max="100" step="5" value="0" required></label>
        <label class="field wide"><span>Узлы с ложным отчётом (через запятую)</span><input id="reportnodes" value="" placeholder="msc2,amf5" maxlength="120"></label>
        <label class="field"><span>Общий сбой зоны</span><select id="sharedzone"><option value="none">Нет</option><option value="epc_outage">EPC недоступна</option><option value="epc_5gc_outage">EPC + 5GC</option><option value="epc_corrupt">EPC искажает</option><option value="epc_5gc_collude">EPC + 5GC в сговоре</option><option value="all_outage">Все недоступны</option></select></label>
        <label class="field"><span>Вероятность сбоя, %</span><input id="sharedprob" type="number" min="0" max="100" value="100"></label>
        <label class="field"><span>Пропуски захвата, %</span><input id="capturemiss" type="number" min="0" max="50" value="0"></label>
        <label class="field"><span>Допуск кворума</span><input id="countdelta" type="number" min="0" max="100" value="0"></label>
      </div><div class="form-bottom"><button type="submit" class="primary" id="run">▶ Запустить моделирование</button>
      <label class="small muted"><input id="attack" type="checkbox" checked> Синтетические атаки</label>
      <button type="button" id="export-simulation" class="secondary" disabled>↓ Скачать JSON</button>
      <span id="run-status" class="inline-status" role="status" aria-live="polite"></span></div></form>
    </div>
    <div class="stats" id="metrics"><div class="card stat"><span class="label">Сообщений</span><span class="value">—</span></div><div class="card stat"><span class="label">Доставлено</span><span class="value">—</span></div><div class="card stat"><span class="label">КИЕ доставлено</span><span class="value">—</span></div><div class="card stat"><span class="label">Тревоги</span><span class="value">—</span></div></div>
    <div class="grid2">
      <section class="card card-inner"><div class="card-head"><h2>Топология сети</h2><span class="chip">2G → 5G</span></div><div class="legend" id="legend"></div><svg id="topology" class="network-svg" viewBox="0 0 980 510" role="img" aria-label="Логическая топология узлов 2G–5G"></svg><p class="hint">Узлы с проблемными КИЕ выделяются красным ободком. Топология логическая, не физическая.</p></section>
      <section class="card card-inner"><div class="card-head"><h2>Контроль и тревоги</h2><span class="small muted" id="alert-count">—</span></div><div id="alerts" class="scroll" aria-live="polite"></div>
      <div class="divider"></div><h3>Динамика событий</h3><div class="mini-bars" id="histogram" role="img" aria-label="Гистограмма событий по интервалам времени"></div><div class="hint">Число модельных событий по десяти равным интервалам</div></section>
    </div>
    <div class="grid2 section-gap">
      <section class="card card-inner"><div class="card-head"><h2>Состояние КИЕ по узлам</h2><span class="chip">HMAC / QUORUM</span></div>
      <div class="scroll"><table><thead><tr><th>Узел</th><th>Результат</th><th>Доставка</th><th>Расхождения</th><th>Кворум</th></tr></thead><tbody id="node-table"></tbody></table></div></section>
      <section class="card card-inner"><div class="card-head"><h2>Зональные признаки</h2><span class="small muted" id="zone-coverage">—</span></div>
      <div class="scroll"><table><thead><tr><th>Узел</th><th>Остаток</th><th>Откл. от медианы</th><th>Ранг</th></tr></thead><tbody id="zone-table"></tbody></table></div></section>
    </div>
    <section class="card card-inner section-gap">
      <div class="card-head"><div><h2>Журнал сигнальных событий</h2><p class="small muted">Последние 300 модельных сообщений, фильтрация выполняется в браузере</p></div><div class="toolbar"><input class="filter" id="event-search" placeholder="Поиск узла или операции" aria-label="Поиск событий">
        <select class="filter" id="event-protocol" aria-label="Фильтр протокола"><option value="">Все протоколы</option></select>
        <span id="event-count" class="small muted"></span></div></div>
      <div class="scroll"><table><thead><tr><th>Время, мс</th><th>Поколение</th><th>Протокол</th><th>Операция</th><th>Маршрут</th><th>Результат</th></tr></thead><tbody id="event-table"></tbody></table></div>
    </section>
  </section>
  <section id="research" hidden>
    <div class="callout">Доступны только встроенные <strong>синтетические</strong> сценарии. Эксперименты не используют личные данные, внешние трассы или закрытые источники. Сравнение не подтверждает промышленную эффективность.</div>
    <div class="card card-inner section-gap">
      <div class="card-head"><div><h2>Выберите исследование</h2><div class="small muted">Разметка не поступает в детекторы, используются фиксированные обучающие источники</div></div></div>
      <form id="study-form" class="toolbar"><select id="study-name" class="filter" aria-label="Исследование">
        <option value="episodes">Эпизоды с неизвестным началом</option>
        <option value="labeled">Размеченные агрегаты</option>
        <option value="zonal">Зональные детекторы</option>
        <option value="clock">Рассинхронизация интервалов</option></select>
        <button type="submit" class="primary" id="study-run">▶ Выполнить эксперимент</button>
        <button type="button" class="secondary" id="export-study" disabled>↓ Скачать сводку</button>
        <span id="study-status" class="inline-status" role="status" aria-live="polite"></span>
      </form></div>
    <div class="study-summary section-gap">
      <section class="card card-inner"><div class="card-head"><h2 id="study-title">Результаты сравнения</h2><span class="chip">SYNTHETIC</span></div>
      <p class="muted small" id="study-description">Запустите исследование для отображения числовых результатов.</p>
      <div class="divider"></div><p class="small muted" id="study-primary"></p><div id="study-bars"></div>
      </section>
      <section class="card card-inner"><h2>Метрики и ограничения</h2><p id="study-scope" class="small muted"></p>
      <div id="study-metrics" class="result-tiles"></div><div id="study-limitations" class="small muted"></div></section>
    </div>
  </section>
  <section id="security" hidden>
    <div class="callout"><strong>Приватные операции отключены в браузере.</strong> Для подписи агрегатов и управления доверенным журналом используется только локальный CLI. Здесь нет полей ввода HMAC-ключей, загрузки операторских файлов и доступа к SQLite.</div>
    <div class="grid2 section-gap">
      <section class="card card-inner"><h2>Жизненный цикл доверия</h2>
      <div class="step"><div class="step-index">1</div><div><h3>Источник и локальная политика</h3><div class="small muted">Уникальные key_id, source_id, lineage_id и секрет от 32 байт; policy хранится вне репозитория.</div></div></div>
      <div class="step"><div class="step-index">2</div><div><h3>Проверка HMAC</h3><div class="small muted">Подпись защищает целый агрегат и разметку, но не гарантирует точность самого измерения.</div></div></div>
      <div class="step"><div class="step-index">3</div><div><h3>Долговременный журнал</h3><div class="small muted">SQLite хранит монотонные sequence. Партия принимается одной транзакцией, повтор отвергается.</div></div></div>
      <div class="step"><div class="step-index">4</div><div><h3>Отзыв и ротация</h3><div class="small muted">Старый key_id блокируется, новый секрет всегда получает новый key_id. Откат базы требует внешней защиты.</div></div></div>
      </section>
      <section class="card card-inner"><h2>Команды на локальном компьютере</h2><p class="small muted">Запускать в терминале, не в веб-форме.</p>
      <div class="code-box"># Проверка без реальных секретов
python -m hetnet durable-replay-demo

# Однократная приватная инициализация
install -d -m 700 "$HOME/.local/share/hetnet-state"
python -m hetnet attestation-init-state \
  --state-db "$HOME/.local/share/hetnet-state/replay.sqlite3"

# Получить состояние (без секретов)
python -m hetnet attestation-state \
  --state-db "$HOME/.local/share/hetnet-state/replay.sqlite3"</div>
      <div class="divider"></div><p class="small muted"><strong>Ограничения:</strong> локальный HMAC подтверждает заявление держателя ключа. Ни операторская разметка, ни физическая независимость датчиков, ни защищённая от отката база данных здесь не подтверждаются.</p></section>
    </div>
  </section>
  <p class="footer-note">HetNet — абстрактная научная модель процедур MAP, Diameter, GTPv2-C, SIP и 5G SBI. Нет реального обмена сигнальными пакетами или сертификации 3GPP Release 18.</p>
</main></div>
<script>
"use strict";
const $=id=>document.getElementById(id);
const state={simulation:null,study:null};
const colors={"2G":"#eeb86b","3G":"#b5a0ee","4G":"#75b6ff","5G":"#5bdfbd","IMS":"#f299b9","shared":"#b5d1da","external":"#ec9295","2G/3G":"#c9b5e9"};
const groups=["2G","2G/3G","3G","4G","IMS","shared","5G","external"];
const descriptions={persistent_report_divergence:"Повторное расхождение",report_integrity_failure:"Ошибка MAC",unconfirmed_divergence:"Нет подтверждения",telemetry_degraded:"Потеря наблюдений",consistent:"Согласованно",insufficient_evidence:"Нет данных",consistent_with_loss:"Согласовано с потерями",consistent_with_observer_outliers:"Большинство согласовано",consistent_with_observer_gaps:"Часть датчиков недоступна",observer_quorum_unavailable:"Нет кворума"};
function add(tag,parent,text,cls){const e=document.createElement(tag);if(text!==undefined&&text!==null)e.textContent=String(text);if(cls)e.className=cls;parent.appendChild(e);return e}
function cell(row,text,cls){return add("td",row,text,cls)}
function numeric(n,decimals){return typeof n==="number"&&Number.isFinite(n)?n.toFixed(decimals):"—"}
function percent(n){return typeof n==="number"&&Number.isFinite(n)?(n*100).toFixed(1)+"%":"—"}
function status(id,message,error){const e=$(id);e.textContent=message;e.classList.toggle("error",!!error)}
function download(data,name){const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});const href=URL.createObjectURL(blob);const a=document.createElement("a");a.href=href;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(href),3000)}
function setView(view){
  ["overview","research","security"].forEach(k=>{$(k).hidden=k!==view});
  document.querySelectorAll(".nav-btn").forEach(btn=>{if(btn.dataset.view===view)btn.setAttribute("aria-current","page");else btn.removeAttribute("aria-current")});
  const titles={overview:["Обзор гетерогенной сети","Интерактивная модель сигнализации, узлового контроля КИЕ и наблюдателей. Все данные синтетические."],research:["Исследовательская лаборатория","Сравнения детекторов и временных эпизодов на встроенных синтетических наборах."],security:["Целостность и доверие","Политика HMAC, защита от повторов и отзыв ключей. Приватные действия доступны только через CLI."]};
  $("page-title").textContent=titles[view][0];$("page-subtitle").textContent=titles[view][1];
}
document.querySelectorAll(".nav-btn").forEach(btn=>btn.addEventListener("click",()=>setView(btn.dataset.view)));
const presets={
  normal:{nodecase:"none",observercase:"none",sharedzone:"none",capturemiss:0,countdelta:0,attack:false,reportnodes:""},
  fault:{nodecase:"report",observercase:"none",sharedzone:"none",capturemiss:0,countdelta:0,attack:false,reportnodes:"msc2,amf5"},
  outage:{nodecase:"none",observercase:"outage",sharedzone:"epc_5gc_outage",sharedprob:100,attack:false,reportnodes:""}
};
document.querySelectorAll("[data-preset]").forEach(btn=>btn.addEventListener("click",()=>{
const preset=presets[btn.dataset.preset];Object.keys(preset).forEach(k=>{$(k).type==="checkbox"?$(k).checked=Boolean(preset[k]):$(k).value=String(preset[k])});
status("run-status","Профиль загружен. Нажмите «Запустить».",false)
}));
function topology(data){
  const svg=$("topology");svg.replaceChildren();
  const positions={};
  groups.forEach((g,gi)=>{const list=data.nodes.filter(n=>n.generation===g);list.forEach((n,i)=>{positions[n.id]={x:55+gi*120,y:55+(i+1)*390/(list.length+1)}})});
  const ns="http://www.w3.org/2000/svg";
  function svgEl(tag,attrs){const e=document.createElementNS(ns,tag);Object.keys(attrs).forEach(k=>e.setAttribute(k,String(attrs[k])));svg.appendChild(e);return e}
  (data.links||[]).forEach(link=>{const a=positions[link.source],b=positions[link.target];if(a&&b)svgEl("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:"#34516c","stroke-width":1.45})});
  const bad=new Set((data.node_evidence?.nodes||[]).filter(n=>["persistent_report_divergence","report_integrity_failure","observer_quorum_unavailable"].includes(n.classification)).map(n=>n.node));
  (data.nodes||[]).forEach(n=>{const p=positions[n.id];if(!p)return;
    const circ=svgEl("circle",{cx:p.x,cy:p.y,r:bad.has(n.id)?11:8.5,fill:colors[n.generation]||"#b6c5d9",stroke:bad.has(n.id)?"#fb8c98":"#11283a","stroke-width":bad.has(n.id)?3:1});
    const title=document.createElementNS(ns,"title");title.textContent=n.id+" · "+n.generation+" · "+n.role;circ.appendChild(title);
    const name=svgEl("text",{x:p.x,y:p.y+25,"text-anchor":"middle",fill:"#dce9fb","font-size":12});name.textContent=n.id;
  });
  const legend=$("legend");legend.replaceChildren();groups.filter(g=>data.nodes.some(n=>n.generation===g)).forEach(g=>{const span=add("span",legend);const mark=add("i",span);mark.style.background=colors[g];add("span",span,g)});
}
function histogram(data){
  const el=$("histogram");el.replaceChildren();const events=data.events||[];const n=10;const counts=Array(n).fill(0);const maxMs=Math.max(1,...events.map(e=>e.time_ms||0));
  events.forEach(e=>{const k=Math.min(n-1,Math.floor((e.time_ms||0)/maxMs*n));counts[k]++});
  const top=Math.max(1,...counts);
  counts.forEach((count,i)=>{const bar=add("div",el);bar.style.height=Math.max(3,Math.round(count/top*108))+"px";bar.dataset.count=String(count);bar.tabIndex=0;bar.setAttribute("aria-label","Интервал "+(i+1)+": "+count+" событий")});
}
function renderMetrics(data){
  const cards=[["Всего сообщений",data.summary?.total_messages],["Доставлено",data.summary?.delivered],["КИЕ доставлено",(data.summary?.cu_delivered||0)+" / "+(data.summary?.cu_observations||0)],["Сработало тревог",data.summary?.alerts]];
  const m=$("metrics");m.replaceChildren();cards.forEach(([label,value])=>{const c=add("div",m,undefined,"card stat");add("span",c,label,"label");add("span",c,value===undefined?"—":value,"value")});
}
function renderNodes(data){
  const table=$("node-table");table.replaceChildren();
  const items=data.node_evidence?.nodes||[];
  items.forEach(n=>{const tr=add("tr",table);cell(tr,n.node,"mono");
    const td=cell(tr);const cls=n.classification||"insufficient_evidence";const badge=add("span",td,descriptions[cls]||cls,"pill");
    if(cls==="persistent_report_divergence"||cls==="report_integrity_failure")badge.classList.add("bad");
    else if(cls!=="consistent"&&cls!=="consistent_with_loss")badge.classList.add("warn");
    cell(tr,(n.delivered||0)+" / "+(n.observations||0),"mono");cell(tr,n.authenticated_mismatches||0,"mono");
    cell(tr,(n.observer_quorum_present||0)+" / "+((n.observer_quorum_present||0)+(n.observer_quorum_missing||0)),"mono");
  });if(!items.length)add("tr",table).appendChild(add("td",document.createDocumentFragment(),"Нет наблюдений"));
  const zone=$("zone-table");zone.replaceChildren();const e=data.zonal_evidence||{};
  $("zone-coverage").textContent="Подтверждённых признаков: "+(e.summary?.node_features||0);
  const frames=e.epochs||[];const last=frames.length?frames[frames.length-1].time_ms:null;
  const features=(e.features||[]).filter(x=>x.time_ms===last).sort((a,b)=>a.zone_rank_desc-b.zone_rank_desc);
  features.forEach(x=>{const tr=add("tr",zone);cell(tr,x.node,"mono");cell(tr,numeric(x.excess_ratio,3),"mono");cell(tr,numeric(x.delta_from_zone_median,3),"mono");cell(tr,x.zone_rank_desc,"mono")});
  if(!features.length){const tr=add("tr",zone);const td=cell(tr,"Недостаточно проверенных наблюдений");td.colSpan=4}
}
function renderAlerts(data){
  const root=$("alerts");root.replaceChildren();const items=data.alerts||[];
  $("alert-count").textContent=items.length+" тревог";
  if(!items.length){add("div",root,"Нет тревог в текущем сценарии","list-empty");return}
  items.slice(0,22).forEach(x=>{const block=add("div",root,undefined,"alert");add("strong",block,(x.category||"Контроль")+" · "+(x.source||"—"));add("p",block,(x.reason||"")+(x.time_ms!==undefined?" · "+x.time_ms+" мс":""))});
}
function renderEventFilter(){
  const root=$("event-protocol");const old=root.value;root.replaceChildren();const empty=add("option",root,"Все протоколы");empty.value="";
  const events=state.simulation?.events||[];const protocols=[...new Set(events.map(e=>e.protocol))].sort();
  protocols.forEach(p=>{const o=add("option",root,p);o.value=p});root.value=protocols.includes(old)?old:"";
}
function renderEvents(){
  const all=(state.simulation?.events||[]).slice(-300);
  const needle=$("event-search").value.toLocaleLowerCase("ru").trim();const protocol=$("event-protocol").value;
  const items=all.filter(e=>(!protocol||e.protocol===protocol)&&(!needle||[e.operation,e.source,e.target,e.protocol,e.outcome].join(" ").toLocaleLowerCase("ru").includes(needle)));
  $("event-count").textContent=items.length+" / "+all.length;const body=$("event-table");body.replaceChildren();
  items.forEach(e=>{const tr=add("tr",body);[e.time_ms,e.generation,e.protocol,e.operation,(e.source||"")+" → "+(e.target||""),e.outcome].forEach(value=>cell(tr,value))});
  if(!items.length){const tr=add("tr",body);const td=cell(tr,"События не найдены");td.colSpan=6}
}
function renderSimulation(data){
  state.simulation=data;$("export-simulation").disabled=false;
  renderMetrics(data);topology(data);histogram(data);renderNodes(data);renderAlerts(data);renderEventFilter();renderEvents();
}
function paramsFromForm(){
const params=new URLSearchParams();
["duration","subscribers","seed","traffic","nodecase","observercase","reportnodes","sharedzone","countdelta"].forEach(key=>params.set(key,$(key).value));
["observerloss","sharedprob","capturemiss"].forEach(key=>params.set(key,String(Number($(key).value)/100)));
params.set("attacks",$("attack").checked?"1":"0");return params
}
async function getJson(url){const response=await fetch(url,{headers:{"X-HetNet-UI":"1"},cache:"no-store"});const payload=await response.json();if(!response.ok)throw Error(payload.error||"HTTP "+response.status);return payload}
async function runSimulation(){
const form=$("controls");if(!form.reportValidity())return;
const button=$("run");button.disabled=true;status("run-status","Моделирование…",false);
try{const data=await getJson("/api/run?"+paramsFromForm().toString());renderSimulation(data);status("run-status","Сценарий завершён · seed "+$("seed").value,false)}
catch(error){status("run-status",error.message,true)}
finally{button.disabled=false}
}
$("controls").addEventListener("submit",e=>{e.preventDefault();runSimulation()});
$("export-simulation").addEventListener("click",()=>{if(state.simulation)download(state.simulation,"hetnet-synthetic-run.json")});
$("event-search").addEventListener("input",renderEvents);$("event-protocol").addEventListener("change",renderEvents);
function renderStudy(report){
  state.study=report;$("export-study").disabled=false;
  $("study-title").textContent=report.title;
  $("study-description").textContent=report.description;
  $("study-primary").textContent=report.primary_label;
  $("study-scope").textContent=report.scope;
  const bars=$("study-bars");bars.replaceChildren();
  report.rows.forEach(row=>{const r=add("div",bars,undefined,"bar-row");add("strong",r,row.label,"small");
    const track=add("div",r,undefined,"bar-track");const fill=add("div",track,undefined,"bar-fill");const value=typeof row.primary==="number"&&Number.isFinite(row.primary)?Math.max(0,Math.min(1,row.primary)):0;fill.style.width=(value*100)+"%";add("span",r,percent(row.primary),"mono small");
  });
  const metrics=$("study-metrics");metrics.replaceChildren();
  const values=[["Строк сравнения",report.rows.length],["Ложные тревоги",report.rows.reduce((n,r)=>n+(r.false||0),0)],["Обнаружено",report.rows.reduce((n,r)=>n+(r.detected||0),0)],["Источник","Синтетика"]];
  values.forEach(([name,value])=>{const c=add("div",metrics,undefined,"result-tile");add("span",c,name,"small muted");add("b",c,value)});
  const limits=$("study-limitations");limits.replaceChildren();(report.limitations||[]).forEach(line=>add("p",limits,"• "+line));
}
async function runStudy(){
  const button=$("study-run");button.disabled=true;status("study-status","Выполняется вычисление…",false);
  try{const name=$("study-name").value;const report=await getJson("/api/study?name="+encodeURIComponent(name));renderStudy(report);status("study-status","Сравнение выполнено",false)}
  catch(error){status("study-status",error.message,true)}
  finally{button.disabled=false}
}
$("study-form").addEventListener("submit",e=>{e.preventDefault();runStudy()});
$("export-study").addEventListener("click",()=>{if(state.study)download(state.study,"hetnet-"+state.study.id+"-synthetic-summary.json")});
runSimulation();
</script></body></html>"""
