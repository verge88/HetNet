# HetNet: единый симулятор сигнализации мобильных сетей 2G–5G

Исследовательский **дискретно-событийный симулятор**, в котором одновременно работают логические подсистемы 2G/3G (SS7/MAP), 4G EPC (Diameter + GTPv2-C), IMS (SIP) и 5G Core (SBI/HTTP/2). Объединяет топологию, часы, абонентов, межпоколенные переходы, унифицированный журнал событий, независимое наблюдение за сигнализацией и детекторы аномалий.

> **Границы соответствия:** набор операций, ролей и протокольных зависимостей согласован с указанными 3GPP/ITU-T/IETF спецификациями на уровне модели. Это **не** реализация полного стека GSM/UMTS/LTE/NR, не передача реальных сигнальных пакетов и не сертифицированное подтверждение соответствия 3GPP. Область охвата и исключения — в [матрице стандартов](docs/standards.md).

## Запуск

Нужен Python 3.10+; для модели и тестов нет сторонних runtime-зависимостей.

```bash
python -m pip install -e .
python -m hetnet run --duration 18 --subscribers 8 --seed 42 --output results
python -m hetnet serve --host 127.0.0.1 --port 8080
```

Откройте http://127.0.0.1:8080 — браузерная панель покажет топологию, счётчики, события, тревоги и позволит запустить новое моделирование. Веб-сервер слушает локальный адрес по умолчанию.

Параметры CLI: `--duration` (секунды), `--subscribers` (не меньше 4), `--seed` (воспроизводимость), `--loss-rate` (вероятность потери на каждом ребре), `--cu-interval` (мс), `--no-attacks` (только штатные процедуры). Команда `python -m hetnet standards` выводит сопоставление операций со спецификациями.

После прогона папка `results/` содержит `result.json`, `summary.json`, `alerts.json`, `topology.json` и `events.csv`. Поле `subject` использует **синтетические псевдонимы**, а не настоящие IMSI/SUPI.

## Что моделируется

- **2G**: MSC/VLR–STP–HLR, процедуры MAP SendAuthenticationInfo и UpdateLocation.
- **3G**: SGSN–STP–HLR, процедуры MAP SendAuthenticationInfo и UpdateGprsLocation (пакетная подсистема).
- **4G**: MME–DRA–HSS, Diameter AIR/AIA и ULR/ULA; MME–SGW, GTPv2-C CreateSessionRequest/Response.
- **IMS**: P-CSCF–S-CSCF, SIP REGISTER, INVITE, 1xx/2xx, ACK и BYE с корреляцией диалога.
- **5G**: gNB/AMF, AUSF, UDM, SMF, NRF, UPF и SEPP; логические запросы 5G SBA к сервисам NFDiscovery, UEAuthentication, UECM, PDU Session, NFManagement.
- **Совместная работа**: перемещение синтетического абонента 2G→3G, 3G→4G, 4G→5G либо 5G→4G; IWF регистрирует межпоколенное **семантическое** событие, после чего выполняется стандартная процедура в целевом поколении. Прямой MAP→SBI wire-трансляции не заявляется.
- **Безопасность и мониторинг**: разграничение операций по ролям, контроль NFProfile, скользящее окно SIP INVITE, SIP ACK-инвариант, контрольные информационные единицы (КИЕ) с HMAC и независимым сравнением счётчиков. Инъекции атак безопасно локальны и не взаимодействуют с реальными сетями.

Схема исследования взята из приложенной диссертации: разделы 3.2–3.8 (отдельные генераторы MAP/Diameter/SIP, общий формат события, КИЕ, инварианты, проверка воспроизводимости) и раздел 2.5 (5G SBA). Это **новая объединённая минимальная реализация**, а не воспроизведение всех моделей, параметров, результатов и ML-классификаторов диссертации.

## Проверка

```bash
python -m unittest discover -s tests -v
```

Тесты проверяют совместное присутствие поколений и стеков, детерминизм, межпоколенные события, корректность SIP ACK, валидацию NFProfile, нарушения политик, КИЕ, потери звеньев и экспорт результатов.

## Следующие этапы для расширенного нормативного соответствия

Для испытаний на уровне реального протокола потребуются отдельные ASN.1 BER кодеки MAP/TCAP/SCCP, Diameter AVP и транспорт (SCTP/TLS/IPsec), SIP transaction timers/IMS AKA, полноценный GTPv2-C, NGAP/NAS/RRC и 5G SBI JSON/OpenAPI/HTTP/2 с TLS/OAuth2/SEPP/N32, а также проверка конкретных версий 3GPP Release и TTCN-3/interop тесты. Такие функции **не** реализованы и не имитируются как будто они проверены.

## Этап 2 — расширенная имитация и научная воспроизводимость

- Пер-узловые потоки в пяти сигнальных доменах с суточной гармоникой, AR(1), семплированием Пуассона и контролем интенсивности через `--traffic-scale`.
- Ограниченная пропускная способность и буферы звеньев, причинная обработка пакетов hop-by-hop, задержки и состояния `CONGESTED`/ `LOST`.
- Состояния процедур 2G/3G, LTE, IMS и 5G с обязательными предшественниками, сопоставлением ответов и тайм-аутами.
- Агрегированные `observations.csv` по окнам ОКС-7 30 с, Diameter 15 с, SIP 20 с; GTP/5G — расширение.
- Экспериментальные серии seed 42–51 с отдельной оценкой message-level precision, recall, FPR, F1 и выборочного стандартного отклонения.
- Таблица конкретных редакций стандартов **3GPP Release 18**: [standards/release18.json](standards/release18.json).

```bash
python -m hetnet run --duration 60 --subscribers 16 --seed 42 --traffic-scale 2 --output results/run
python -m hetnet experiment --duration 18 --subscribers 8 --start-seed 42 --runs 10 --output results/experiment
python -m unittest discover -s tests -v
```

Полные допущения и ограничения: **[docs/validation-stage2.md](docs/validation-stage2.md)**. Генератор и его параметры являются новыми синтетическими допущениями: **это не** воспроизведение исходных 24-часовых наборов из диссертации и **не** сертифицированная протокольная реализация.

## Этап 3 — офлайн-проверка форматов и независимая оценка по эпизодам

Новые команды работают **только с локальными файлами или синтетическими событиями**. Никакие запросы в реальные мобильные сети не отправляются.

```bash
# Реальный бинарный envelope Diameter v1 (синтетические поля, без AVP)
python -m hetnet wirecheck --protocol diameter --hex 010000148000013e010000230000000100000002
# Калибровка по вымышленным агрегированным счётчикам
python -m hetnet calibrate --input examples/synthetic_aggregate_counts.json --output results/calibration.json
# Научная оценка по эпизодам: обучение на одних seed, тест на других
python -m hetnet validate --duration 18 --subscribers 8 --traffic-profile results/calibration.json --output results/stage3
# Только легитимные события: FPR при потере пакетов и росте нагрузки
python -m hetnet stress --duration 18 --subscribers 8 --traffic-profile results/calibration.json --output results/stress
```

Подробнее: [методика этапа 3](docs/validation-stage3.md) и [фактические результаты CI](docs/results-stage3.md). Валидаторы реализуют **ограниченный синтаксический слой** SIP, Diameter/AVP, GTPv2-C и HTTP/2; их принятие сообщения **не означает** полного соответствия RFC/3GPP или сетевой совместимости. Отсутствуют MAP/TCAP BER, реальная NGAP/NAS и 5G SBI/OpenAPI. Эксперимент на синтетических эпизодах специально отделён от метрик отдельных сообщений и от безопасности КИЕ.

## Этап 4 — доказательные признаки контроля КИЕ и потери

Симулятор отдельно отслеживает: (1) корректно подписанный, но не
соответствующий независимому учёту отчёт узла, (2) нарушение
подписи при изменении контрольного сообщения в пути и
(3) обычную потерю контрольного ответа. Выводы основаны на
отчётах CU.Reconciliation; событие потери само по себе не доказывает
компрометацию.

    python -m hetnet run --duration 18 --subscribers 8 --no-attacks --node-case report --output results/report-only
    python -m hetnet run --duration 18 --subscribers 8 --no-attacks --node-case tamper --output results/tamper-only
    python -m hetnet node-study --duration 18 --subscribers 8 --start-seed 42 --runs 6 --loss-rates 0,0.1,0.35 --output results/node-study

Экспорт: node_evidence.json и node_study.json. На веб-панели отображаются
свидетельства для каждого узла и доля доставки КИЕ.

**[Методика этапа 4](docs/validation-stage4.md)** /
**[Результаты эксперимента](docs/results-stage4.md)**.

КИЕ — исследовательский метод, не спецификация 3GPP. Различие
подписанного отчёта и независимого наблюдения остаётся подозрением,
а не доказательством взлома. Совместимость со стеком реального
оператора по-прежнему не заявляется.

## Этап 5 — наблюдатели из трёх независимых доменов

Для каждого опроса КИЕ моделируются три раздельно подписанных голоса наблюдения Legacy/EPC/5GC. Сравнение отчёта с независимыми счётчиками проводится только при проверенном большинстве **2 из 3**. Дубликаты, неверные подписи и устаревшие голоса не учитываются. Недостаток кворума означает **неопределённость**, а не доказательство взлома.

```bash
python -m hetnet run --duration 18 --subscribers 8 --no-attacks --node-case none --observer-case one_faulty --output results/observer-single
python -m hetnet run --duration 18 --subscribers 8 --no-attacks --node-case report --observer-case two_colluding --output results/collusion
python -m hetnet zone-study --duration 18 --subscribers 8 --runs 6 --observer-loss-rates 0,0.2,0.45 --output results/zone-study
```

Сценарии `--observer-case`: `none`, `one_faulty`, `two_colluding`, `outage`, `mixed`, `bad_mac`, `stale`. В `run` доступен параметр `--observer-loss-rate` (0…1). Веб-панель показывает доступность кворума, отклонённые/отсутствующие голоса и несогласное меньшинство; `node_evidence.json` и `zone_study.json` пригодны для повторной обработки.

**[Методика 5-го этапа](docs/validation-stage5.md)** · **[Результаты и ограничения](docs/results-stage5.md)**.

**Важно:** при сговоре двух из трёх наблюдателей большинство может обвинить честный узел и пропустить подделку. Это демонстрируемое ограничение модели, а не успешно отражённая атака. Административные домены и подписи — синтетические исследовательские конструкции, а не стандартный механизм 3GPP.
