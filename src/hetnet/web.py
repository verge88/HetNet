"""Self-contained local dashboard; no third-party service or network emission."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlsplit

from .simulator import Scenario, Simulator

HTML = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HetNet — 2G–5G Simulator</title>
<style>
:root{font:14px/1.5 system-ui,-apple-system,sans-serif;color:#e9efff;background:#0a1020}
*{box-sizing:border-box}body{max-width:1300px;margin:0 auto;padding:30px 22px}
h1{font-size:29px;margin:0 0 4px;letter-spacing:-.6px}p{color:#9eacc7}
header{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:center}
.panel{background:#121d33;border:1px solid #2b3853;border-radius:13px;padding:18px;margin:16px 0}
.controls{display:flex;gap:12px;align-items:end;flex-wrap:wrap}
label{display:grid;gap:5px;color:#b6c6e0}input,select{background:#0b1426;color:white;border:1px solid #40516e;padding:10px;border-radius:8px;width:125px}
input[type=checkbox]{width:auto;accent-color:#46c7a9}
button{background:#40bda1;color:#08211a;border:0;border-radius:9px;padding:11px 19px;font-weight:750;cursor:pointer}
.grid{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:12px}.metric{background:#182844;border-radius:10px;padding:15px}.metric strong{display:block;font-size:27px}
.small{color:#9eacc7;font-size:12px}.two{display:grid;grid-template-columns:2fr 1fr;gap:16px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:9px;border-bottom:1px solid #2b3853;font-size:12px}
th{color:#b2c6e5}tr:hover{background:#1c2a42}.scroll{overflow:auto;max-height:385px}
svg{width:100%;height:auto;min-height:380px}.legend{display:flex;gap:14px;flex-wrap:wrap}
.dot{display:inline-block;border-radius:50%;width:10px;height:10px;margin-right:5px}
@media(max-width:840px){.two{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<header><div><h1>HetNet <span style="color:#40bda1">2G–5G</span></h1>
<p>Единая имитация сигнализации · 2G/3G MAP · 4G Diameter/GTP · IMS SIP · 5G SBA</p></div>
<div class="small">Модель уровня событий, не реальная операторская сеть</div></header>
<div class="panel"><form id="controls" class="controls">
<label>Время, с<input id="duration" type="number" min="5" max="3600" value="18"></label>
<label>Абоненты<input id="subscribers" type="number" min="4" max="300" value="8"></label>
<label>Seed<input id="seed" type="number" value="42"></label>
<label>Фоновая нагрузка, ×<input id="traffic" type="number" min="0" max="25" step="0.5" value="1"></label>
<label>Сценарий КИЕ<select id="nodecase"><option value="auto">Авто</option><option value="none">Норма</option><option value="report">Отчёт узла</option><option value="tamper">Изменение в пути</option><option value="both">Оба</option></select></label>
<label>Наблюдатели<select id="observercase"><option value="none">3 исправны</option><option value="one_faulty">1 подделывает</option><option value="two_colluding">2 в сговоре</option><option value="outage">Нет кворума</option><option value="mixed">Подделка + потеря</option><option value="bad_mac">Повреждён MAC</option><option value="stale">Устаревшая подпись</option></select></label>
<label>Потери голосов, %<input id="observerloss" type="number" min="0" max="100" step="5" value="0"></label>
<label>Узлы с подделкой отчёта<input id="reportnodes" placeholder="msc2,amf5" value=""></label>
<label>Общий сбой зоны<select id="sharedzone"><option value="none">Нет</option><option value="epc_outage">EPC недоступна</option><option value="epc_5gc_outage">EPC + 5GC недоступны</option><option value="epc_corrupt">EPC искажает</option><option value="epc_5gc_collude">EPC + 5GC в сговоре</option><option value="all_outage">Все недоступны</option></select></label>
<label>Вероятность общего сбоя, %<input id="sharedprob" type="number" min="0" max="100" step="5" value="100"></label>
<label style="align-self:center">Синтетические атаки<input id="attack" type="checkbox" checked></label>
<button type="submit">Запустить моделирование</button></form></div>
<div class="grid" id="metrics"></div>
<div class="two"><section class="panel"><h3>Топология гетерогенной сети</h3>
<div class="legend" id="legend"></div><svg id="map" viewBox="0 0 900 470" aria-label="Топология сети"></svg></section>
<section class="panel"><h3>События контроля</h3><div id="alerts" class="scroll"></div></section></div>
<section class="panel"><h3>КИЕ: независимый контроль отчётов узлов</h3>
<p>Рассогласование отчёта, нарушение MAC и потери контроля различаются; это исследовательские свидетельства, а не доказанная компрометация.</p>
<div class="scroll"><table><thead><tr><th>Узел</th><th>Классификация</th><th>Доставлено/попыток</th><th>Несовпадений</th><th>MAC ошибок</th><th>Кворум</th><th>Меньшинство / недействительные</th></tr></thead><tbody id="cu-nodes"></tbody></table></div></section>
<section class="panel"><h3>Общие сбои зон наблюдения</h3>
<p>Симптомы агрегируются только по заново проверенным подписям наблюдателей и общей эпохе. Несогласие большинства не является доказательством виновности датчика.</p>
<div id="domain-summary" class="small"></div>
<div class="scroll"><table><thead><tr><th>Эпоха, мс</th><th>Отсутствующие домены</th><th>Нет кворума (узлы)</th><th>Общие признаки</th></tr></thead><tbody id="zone-events"></tbody></table></div></section>
<section class="panel"><h3>Журнал сигнальных событий</h3><div class="scroll"><table>
<thead><tr><th>мс</th><th>Поколение</th><th>Протокол</th><th>Операция</th><th>Источник → Адресат</th><th>Результат</th></tr></thead>
<tbody id="events"></tbody></table></div></section>
<p>Standards mapping: ITU-T Q.700, 3GPP TS 29.002, 29.272, 29.274, 24.229, 23.501, 29.500/502/503/509/510, 33.501, RFC 3261/6733/9113. Это не испытание соответствия 3GPP.</p>
<script>
const colors={'2G':'#e9a448','3G':'#9b8bea','4G':'#5caaef','5G':'#43c6a6','IMS':'#e887b6','shared':'#d2d8e8','external':'#f07d7d','2G/3G':'#c3a1ee'};
const $=id=>document.getElementById(id);
function add(tag,parent,text){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;parent.appendChild(e);return e;}
function draw(data){
const svg=$('map');svg.replaceChildren();const groups={};
data.nodes.forEach(n=>{(groups[n.generation]||(groups[n.generation]=[])).push(n)});
const order=['2G','2G/3G','3G','4G','IMS','shared','5G','external'];
const coords={};order.forEach((group,i)=>{const list=groups[group]||[];
list.forEach((node,j)=>{coords[node.id]={x:65+i*110,y:50+(j+1)*385/(list.length+1)}})});
function el(tag,attrs){const e=document.createElementNS('http://www.w3.org/2000/svg',tag);
Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,String(v)));svg.appendChild(e);return e;}
data.links.forEach(l=>{const a=coords[l.source],b=coords[l.target];
el('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:'#405474','stroke-width':1.6})});
data.nodes.forEach(n=>{const p=coords[n.id],fill=colors[n.generation]||'#ccc';
el('circle',{cx:p.x,cy:p.y,r:9,fill});const t=el('text',{x:p.x,y:p.y+25,'text-anchor':'middle',fill:'#dce7fa','font-size':12});t.textContent=n.id});
const legend=$('legend');legend.replaceChildren();
order.filter(k=>groups[k]).forEach(k=>{const span=add('span',legend);const dot=add('span',span);
dot.className='dot';dot.style.background=colors[k];span.appendChild(document.createTextNode(k))});
}
function render(data){
const s=data.summary,m=$('metrics');m.replaceChildren();
[['Сообщений',s.total_messages],['Доставлено',s.delivered],['КИЕ доставлено',s.cu_delivered+'/'+s.cu_observations],['Тревог',s.alerts]]
.forEach(([name,value])=>{const c=add('div',m);c.className='metric';
const k=add('span',c,name);k.className='small';add('strong',c,String(value))});
draw(data);const z=data.domain_evidence||{}, zs=z.summary||{};
$('domain-summary').textContent='Эпох с общей потерей: '+(zs.epochs_with_shared_missing||0)+'; без межузлового кворума: '+(zs.epochs_with_quorum_loss||0)+'; общие несовпадающие голоса: '+(zs.epochs_with_shared_outlier||0);
const zbody=$('zone-events');zbody.replaceChildren();
(z.epochs||[]).filter(e=>e.patterns.length||e.cross_node_quorum_loss).slice(-12).forEach(e=>{
const tr=add('tr',zbody);
[e.time_ms,e.missing_domains.join(', ')||'—',e.quorum_lost_nodes.join(', ')||'—',e.patterns.map(p=>p.kind+' '+p.observer+' ('+p.affected_count+')').join('; ')||'—'].forEach(v=>add('td',tr,String(v)));
});
const cues=$('cu-nodes');cues.replaceChildren();
const descriptions={persistent_report_divergence:'Повторное рассогласование',
report_integrity_failure:'Ошибка MAC (источник не определён)',
unconfirmed_divergence:'Пока не подтверждено',telemetry_degraded:'Потеря наблюдений',
consistent:'Согласованно',insufficient_evidence:'Недостаточно данных',
consistent_with_loss:'Согласованно, потеря КИЕ',
consistent_with_observer_outliers:'Согласовано с большинством; есть меньшинство',
consistent_with_observer_gaps:'Часть контрольных доменов недоступна',
observer_quorum_unavailable:'Нет независимого кворума'};
(data.node_evidence?.nodes||[]).forEach(n=>{
const tr=add('tr',cues);
[n.node,descriptions[n.classification]||n.classification,
n.delivered+'/'+n.observations,n.authenticated_mismatches,n.invalid_macs,
n.observer_quorum_present+'/'+(n.observer_quorum_present+n.observer_quorum_missing),
Object.entries(n.observer_outliers||{}).map(([key,v])=>key+':'+v).join(', ')+'; недост. '+Object.values(n.observer_invalid||{}).reduce((a,b)=>a+b,0)]
.forEach(v=>add('td',tr,String(v)))});
const alerts=$('alerts');alerts.replaceChildren();
if(!data.alerts.length)add('p',alerts,'Тревог нет');
data.alerts.forEach(a=>{const p=add('p',alerts);const b=add('strong',p,a.category+' · '+a.source);
add('div',p,a.reason+' ('+a.time_ms+' мс)')});
const tb=$('events');tb.replaceChildren();data.events.slice(-250).forEach(e=>{
const tr=add('tr',tb);[e.time_ms,e.generation,e.protocol,e.operation,e.source+' → '+e.target,e.outcome]
.forEach(value=>add('td',tr,String(value)))});
}
$('controls').addEventListener('submit',async e=>{e.preventDefault();const button=document.querySelector('button');button.disabled=true;button.textContent='Вычисление...';
try{const p=new URLSearchParams({duration:$('duration').value,subscribers:$('subscribers').value,
seed:$('seed').value,traffic:$('traffic').value,
nodecase:$('nodecase').value,observercase:$('observercase').value,
observerloss:String(Number($('observerloss').value)/100),
reportnodes:$('reportnodes').value,sharedzone:$('sharedzone').value,
sharedprob:String(Number($('sharedprob').value)/100),
attacks:$('attack').checked?'1':'0'});
const res=await fetch('/api/run?'+p.toString());const payload=await res.json();
if(!res.ok)throw new Error(payload.error||'HTTP '+res.status);render(payload)}
catch(err){alert(err.message)}finally{button.disabled=false;button.textContent='Запустить моделирование'}});
$('controls').dispatchEvent(new Event('submit'));
</script></body></html>"""


def serve_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = urlsplit(self.path)
            if path.path == "/":
                payload = HTML.encode("utf-8")
                self._send(200, "text/html; charset=utf-8", payload)
                return
            if path.path != "/api/run":
                self._send(404, "application/json", b'{"error":"not found"}')
                return
            try:
                params = parse_qs(path.query)
                def number(name: str, default: str) -> int:
                    return int(params.get(name, [default])[0])
                duration = number("duration", "18")
                subscribers = number("subscribers", "8")
                if not 5 <= duration <= 3600 or not 4 <= subscribers <= 300:
                    raise ValueError("Dashboard limits: duration 5..3600 s, subscribers 4..300")
                traffic = float(params.get("traffic", ["1"])[0])
                if not 0 <= traffic <= 25:
                    raise ValueError("Dashboard traffic scale must be 0..25")
                scenario = Scenario(
                    traffic_scale=traffic,
                    node_case=params.get("nodecase", ["auto"])[0],
                    observer_case=params.get("observercase", ["none"])[0],
                    observer_loss_rate=float(params.get("observerloss", ["0"])[0]),
                    report_fault_nodes=tuple(filter(None, (
                        n.strip() for n in params.get("reportnodes", [""])[0].split(",")))),
                    shared_zone_case=params.get("sharedzone", ["none"])[0],
                    shared_zone_probability=float(params.get("sharedprob", ["1"])[0]),
                    duration_s=duration,
                    subscribers=subscribers,
                    seed=number("seed", "42"),
                    inject_attacks=params.get("attacks", ["1"])[0] == "1",
                )
                result = Simulator(scenario).run()
                payload = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", payload)
            except (TypeError, ValueError) as error:
                self._send(400, "application/json; charset=utf-8",
                           json.dumps({"error": str(error)}).encode("utf-8"))

        def _send(self, status: int, mime: str, payload: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer((host, port), Handler)
    print("HetNet dashboard: http://{}:{}/".format(host, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
