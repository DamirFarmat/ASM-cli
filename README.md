# ASM CLI

Модульный CLI-инструмент для пассивной разведки доменов, IP и URL.

## Что умеет

- DNS/Email health без внешних API (`--dns-manual`)
- Глубокая DNS-разведка с сабдоменами, ASN, Geo, InternetDB (`--dnsdump`)
- DNS resolve/reverse (`--resolve`)
- Анализ HTTP security headers (`--headers`)
- Fingerprint веб-технологий:
  - `--web-version` (python-Wappalyzer)
  - `--web-test` (Wappalyzer Next CLI)
  - `--web` (технологии + CVE/EOL enrichment)
- CVE/EOL enrichment по web JSON (`--vuln`)
- Поиск CVE по ПО и версии (`--cve`)
- TLS/SSL аудит сертификата и протоколов (`--cert`)
- Поиск секретов в JS (`--jsminer`)
- Поиск поддоменов через Yandex dork (`--dork`)

## Быстрый старт

### Установка

Вариант 1 (рекомендуется):

```bash
pipx install .
asm -h
```

Вариант 2 (локально):

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
python asm.py -h
```

### Файл целей

Поддерживаются `.txt` и `.csv` (по одной цели в строке):

```txt
example.com
8.8.8.8
https://example.org
```

## Использование

### Основные режимы

```bash
# DNS/Email checks без API
asm --dns-manual -f targets.txt --html --json

# Resolve/reverse
asm --resolve -f targets.txt

# Глубокая DNS-разведка
asm --dnsdump -f targets.txt -o reports/dnsdump.json

# Сетевая разведка IP
asm --network 8.8.8.8 1.1.1.1 --html --json

# HTTP Security Headers
asm --headers example.com --html

# Технологии (python-Wappalyzer)
asm --web-version example.com --html

# Технологии (Wappalyzer Next)
asm --web-test example.com --html

# Комбинированный web + vuln
asm --web example.com --html

# Отдельный vuln enrichment из JSON
asm --vuln -i reports/web_analyzer_report_YYYYMMDD_HHMMSS.json \
  --json-out reports/web_enriched.json \
  --csv-out reports/web_enriched.csv

# TLS/SSL аудит
asm --cert example.com --html --json

# JS Miner
asm --jsminer -u https://example.com -o reports/jsminer.json --threads 20

# Поиск поддоменов через Yandex dork
asm --dork example.com --dork-pages 3 -o reports/dork.json

# CVE lookup по ПО и версии
asm --cve -s nginx -v 1.28.0 -o reports/cve_nginx_1.28.0.json
```

### Форматы вывода

- `--html`: сохранить HTML-отчёт в `reports/`
- `--json`: сохранить JSON-отчёты (для поддерживающих модулей)
- `--json-only`: печатать только JSON в stdout
- `-o/--output`: явный путь файла для `--dnsdump`, `--jsminer`, `--dork` и `--cve`

## Требования по окружению

### Базовые

- Python >= 3.8
- Установленные зависимости из `requirements.txt`

### Для `--web-test` (Wappalyzer Next)

- доступная в PATH команда `wappalyzer`
- Firefox
- geckodriver

Проверка:

```bash
wappalyzer --help
```

### API ключи

Сейчас для основных режимов обязательные ключи не требуются.

Опционально:

- `--nvd-api-key` для повышения лимитов NVD в `--vuln`/`--web`

Пример `.env`:

```env
NVD_API_KEY=your_nvd_key
```

## Карта модулей (проверено по текущему коду)

| Модуль | Роль | Статус в CLI |
|---|---|---|
| `asm.py` | Главный entrypoint/роутинг флагов | Активен |
| `utils/target_loader.py` | Чтение/валидация целей из файла | Активен |
| `utils/url_resolver.py` | Browser-like URL resolve (https/http + redirects) | Активен |
| `modules/resolve.py` | DNS resolve/reverse | Активен (`--resolve`) |
| `modules/dns_manual.py` | DNS/Email checks без API | Активен (`--dns-manual`) |
| `modules/dnsdump_main.py` + `modules/dnsdump/*` | Глубокая DNS-разведка | Активен (`--dnsdump`) |
| `modules/network.py` | InternetDB анализ IP | Активен (`--network`) |
| `modules/header_analyzer.py` | HTTP security headers | Активен (`--headers`) |
| `modules/web_analyzer.py` | Fingerprint через python-Wappalyzer | Активен (`--web-version`, `--web`) |
| `modules/web_analyzer_next.py` | Fingerprint через Wappalyzer Next CLI | Активен (`--web-test`) |
| `modules/vuln.py` | CVE/EOL enrichment (NVD + endoflife.date) | Активен (`--vuln`, `--web`) |
| `modules/cve.py` | CVE lookup по ПО/версии через NVD | Активен (`--cve`) |
| `modules/cert.py` | TLS/SSL анализ | Активен (`--cert`) |
| `modules/jsminer.py` | Поиск секретов в JS | Активен (`--jsminer`) |
| `modules/reporters.py` | HTML/console репортеры | Активен (вспомогательный) |
| `modules/mxtoolbox_dns.py` | Интеграция с MXToolbox API | В кодовой базе, но не подключен к CLI-флагу |

## Важные замечания

- Файл `pyproject.toml` содержит заглушки в metadata (`Your Name`, `you@example.com`).
- В текущем CLI режимы задаются флагами (не subcommands).
- Для `--jsminer` опция `--no-sourcemaps` сейчас помечена как резервная (в коде sourcemap-поиск не реализован).

## Разработка

Проверка синтаксиса:

```bash
python -m compileall asm.py modules utils
```

Проверка help:

```bash
asm -h
# или
python asm.py -h
```
