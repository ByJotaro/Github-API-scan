# Secret Scanner Pro

<p align="center">
  <b>Поиск API-ключей · валидация · локальный OpenAI-совместимый прокси</b>
</p>

<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/lang-English-2ea44f?style=for-the-badge" alt="English"/></a>
  <a href="./README.ru.md"><img src="https://img.shields.io/badge/lang-Русский-0052cc?style=for-the-badge" alt="Русский"/></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT"/>
  <img src="https://img.shields.io/badge/TUI-Textual-black?logo=windowsterminal" alt="Textual"/>
  <img src="https://img.shields.io/badge/sources-8-informational" alt="8 sources"/>
</p>

<p align="center">
  <img src="assets/tui-dashboard.png" alt="TUI dashboard" width="920"/>
</p>

> Полная документация на английском (и RU-секция в том же файле): **[README.md](./README.md)**  
> Ниже — чистая русская страница (удобно для закладок).

---

## О проекте

Операторский TUI: **11 источников**, валидация **30+ платформ**, пул confirmed-моделей, раздача через **OpenAI-совместимый** прокси `:8818`.

> Только исследования / обучение / системы с разрешением.

## Возможности

| Блок | Содержание |
|------|------------|
| Источники | GitHub · Gist · GitLab · Paster · Pastebin · Realtime · MCP · CodeGraph · Telegram · HuggingFace · веб-дорки |
| TUI | Тёмный дашборд, воркеры, ключи, модели, API-пул |
| Прокси | `/v1/chat/completions` + stream, sticky / round-robin |
| Windows | `start_tui.bat` · `start_scanner.bat` |

## Скриншоты

На всю ширину (не в таблице — иначе GitHub делает картинки мизерными):

**Дашборд**

<p align="center">
  <img src="assets/tui-dashboard.png" alt="Дашборд" width="100%"/>
</p>

**Ключи**

<p align="center">
  <img src="assets/tui-keys.png" alt="Ключи" width="100%"/>
</p>

**API**

<p align="center">
  <img src="assets/tui-api.png" alt="API pool" width="100%"/>
</p>

## Быстрый старт

```bash
git clone <url> Github-API-scan
cd Github-API-scan
pip install -e .   # одна команда: зависимости + лаунчер `ascan`
copy config_local.py.example config_local.py
```

Файл токенов (полный путь):

```text
C:\Users\<вы>\Github-API-scan\config_local.py
```

```python
GITHUB_TOKENS = ["ghp_ВАШ_ТОКЕН"]
```

```bash
ascan            # TUI из любого места
# или: ./start_tui.sh | start_tui.bat | python main_optimized.py
# обновление без потери ключей/БД: ascan upgrade
```

## Какие ключи нужны

| Переменная / файл | Обязательно | Что даёт | Где взять |
|---|---|---|---|
| `GITHUB_TOKENS` (список через запятую) | **да, иначе скан медленный** | GitHub Code Search: без токена 10 запросов/мин, с токеном 30/мин **на каждый** токен. Нужны 4–10 живых токенов. | https://github.com/settings/tokens — classic, scope `public_repo` (для гистов добавьте `gist`) |
| `PASTEBIN_API_KEY` | **нет** | Scraping API (`scrape.pastebin.com`, листинг + raw) **не принимает ключ**: доступ только по IP-whitelist, нужен PRO-аккаунт и статический IP. Developer key из `pastebin.com/doc_api` — только для создания паст. | https://pastebin.com/doc_scraping_api |
| `PROXY_URL` | нет | Исходящий HTTP-прокси для GitHub/Pastebin | — |

Остальные источники (GitLab, SourceGraph, MCP/Smithery, Paster) работают без ключей на публичных лимитах: медленно, но без регистрации. Токены GitLab/SourceGraph в коде пока не поддерживаются.

## Прокси

```text
http://127.0.0.1:8818/v1
```

## Keyless-источники (2026-10)

| Источник | Как работает | Замер |
|---|---|---|
| **HuggingFace** | Публичный полнотекстовый индекс `/api/search/full-text` опрашивается по префиксам ключей (`AIzaSy`, `ghp_`, `sk-proj-`, `gsk_`, `fc-`); найденные `app.py` и файлы датасетов качаются в raw и парсятся. `offset` индекс игнорирует, поэтому глубина набирается разбиением запроса по символам (префикс + символ) с круговым курсором. | 2 Gemini-ключа из 12 файлов за первый цикл |
| **Telegram** | Публичные веб-превью `t.me/s/<channel>` — обычный HTML, без аккаунта и токена. Сообщения парсятся, дедуплицируются по id, к тексту применяются шаблоны ключей. Каналы настраиваются через `TELEGRAM_CHANNELS`; найденные веб-поиском добавляются сами. | 17 сообщений, 0 ключей в текущих постах |
| **Веб-дорки** | Операторные запросы (`site:t.me "AIzaSy"` и т.п.) идут через Google Custom Search при заданных `GOOGLE_CSE_KEY`/`GOOGLE_CSE_CX`, иначе через Brave → DuckDuckGo HTML. Ссылки `t.me/...` становятся каналами Telegram-источника, остальные страницы скачиваются и парсятся. 429/403 отправляет провайдера в 30-минутный кулдаун; CSE-путь упирается в 90 запросов из бесплатных 100/сутки. | 6 каналов с одного дорка; голый google.com/search отдаёт JS-оболочку без ссылок |

## Отчёты, allowlist и обслуживание БД

```bash
# машинный отчёт для CI (SARIF 2.1.0, ключи всегда маскируются)
python main_optimized.py --export-sarif report.sarif

# текстовые экспорты; --redact маскирует значения (sk-pro…UVWX)
python main_optimized.py --export keys.txt --redact
python main_optimized.py --export-csv keys.csv --redact

# подавить известный шум (fingerprint из CSV или platform:key)
python main_optimized.py --suppress openai:sk-... --reason "пример из доков"
python main_optimized.py --list-suppressions
python main_optimized.py --unsuppress 0ae94e367bfc1518

# удалить исторический мусор aws_secret_key (gzip-бэкап -> DELETE -> VACUUM)
python main_optimized.py --purge-junk --purge-dry-run
python main_optimized.py --purge-junk --purge-backup aws_junk.jsonl.gz
```

#### Списки моделей

`GET /models` перечитывается у каждого провайдера, где есть живой ключ,
поэтому вкладка «Модели» и `/v1/models` прокси следуют реальности: новая
модель появляется без перевалидации ключа, а исчезнувшая снимается с
подтверждения при первом пропуске и удаляется после трёх пропусков подряд
(relay с урезанным списком не может стереть рабочие модели).

```bash
python main_optimized.py --refresh-models            # все эндпоинты
python main_optimized.py --refresh-models --models-limit 20
python main_optimized.py --refresh-models --models-base-url https://api.deepseek.com/v1
```

Прокси делает то же в фоне (первый прогон через 90 с после старта, далее раз
в час с окном 6 часов на эндпоинт) и раз в 5 минут сверяет `active_pool`,
поэтому ротация ключей и изменения у провайдера доходят до `/v1/models` без
перезапуска. Принудительно — `POST /admin/refresh-models` (тело
`{"limit": N, "base_url": "…"}`), в TUI — кнопка «Обновить у провайдеров».

Подавленные находки не попадают ни в один экспорт (TXT / CSV / SARIF).
Разрушительные команды (`--reset-db`, `--purge-junk`) спрашивают подтверждение; для неинтерактивного запуска добавьте `--yes`.

## Тесты

```bash
python -m pytest tests/ -q
```

## Лицензия

[MIT](LICENSE)
