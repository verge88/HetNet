# Матрица стандартов и границ реализации

| Домен | Нормативные документы | Что есть в HetNet | Чего нет |
|---|---|---|---|
| ОКС-7, GSM/UMTS | [ITU-T Q.700](https://www.itu.int/rec/T-REC-Q.700/en), [3GPP TS 29.002](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1450) | Структура MSC/SGSN–STP–HLR, MAP аутентификация/регистрация | Реальный MTP/SCCP/TCAP, ASN.1, SIGTRAN |
| LTE/EPC | [3GPP TS 29.272](https://portal.3gpp.org/Specifications.aspx), [RFC 6733](https://www.rfc-editor.org/info/rfc6733/), [3GPP TS 29.274](https://portal.3gpp.org/Specifications.aspx) | MME–HSS AIR/AIA, ULR/ULA, MME–SGW GTPv2-C Create Session | Diameter AVP, GTP payloads, LTE NAS/S1AP, bearer QoS |
| IMS | [RFC 3261](https://www.rfc-editor.org/info/rfc3261/), [3GPP TS 24.229](https://portal.3gpp.org/Specifications.aspx), [TS 23.228](https://portal.3gpp.org/Specifications.aspx) | REGISTER, INVITE, provisional/final responses, ACK, BYE и корреляция | Полная транзакционная машина, IMS AKA, SDP/RTP |
| 5G 5GC/SBA | [3GPP TS 23.501](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3144), [TS 29.500](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3338), [TS 29.510](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3345), TS 29.502/29.503/29.509 | Роли AMF, SMF, UDM, AUSF, NRF; сервисные операции NFDiscovery/NFManagement/UECM/UEAuthentication/PDU Session; проверка NFProfile | Реальные OpenAPI/JSON по версиям release, HTTP/2 кадры и NGAP/NAS |
| Защита 5G | 3GPP TS 33.501, [RFC 9113](https://www.rfc-editor.org/info/rfc9113/) | Проверка прав сервисов, моделирование недоверенного источника, обнаружение изменений NFProfile | TLS, OAuth2, SEPP/N32/PRINS, криптографическая авторизация сетевых функций |
| Межпоколенное взаимодействие | 3GPP TS 23.401 / TS 23.501 | Корреляция mobility-ID и последовательные процедуры целевых сетей | Реальные S3/S4/N26 и преобразования контекста, NSA Option 3 |
| КИЕ | Исследовательский метод из диссертации (гл. 2–3) | Подпись имитационного отчёта и независимый транзитный контроль | Не является стандартизованным 3GPP/ITU-T wire-протоколом |

## Профиль проверки

- **Моделируемый уровень:** архитектура и операции сигнальной плоскости с дискретными событиями, без пакетного кодирования.
- **Проверяемые свойства:** детерминизм по seed, связность маршрутов, роли источников, последовательности SIP, допустимые переходы NFProfile, изменения состояния абонента, реакция на потери и синтетические инъекции.
- **Контроль истинности:** метки `attack` используются для оценки, но решение о тревоге принимается по политике, счётчикам и корреляции.
- **Не подтверждено:** соответствие точным требованиям какой-либо 3GPP Release, протокольная/радиочастотная совместимость, стойкость криптографии, производительность промышленного ядра.
- **Версионирование:** прежде чем говорить о формальном соответствии, нужно зафиксировать релиз и редакцию каждой TS и выполнить независимые conformance/interoperability тесты.

Основой для унифицированного формата события служат таблицы 3.4–3.5 и раздел 3.6 диссертации; исходная работа описывает отдельные реализации ОКС-7, Diameter и SIP. Компонент 5G и единый цикл mobility здесь расширяют схему исследования.
