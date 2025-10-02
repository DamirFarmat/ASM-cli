# ASM - Модульное приложение для пассивной разведки

Модульное CLI-приложение для пассивной разведки доменов и IP-адресов: DNS/Email health, веб‑технологии (в т.ч. Wappalyzer Next), проверка security‑заголовков, сетевая разведка, TLS/SSL.

## Возможности

### 🔍 DNS-анализ через MXToolbox API
- Проверка Email Health и Domain Health
- Анализ SPF, DMARC, DKIM записей
- Интеграция с MXToolbox API

### 🛠️ Ручной DNS-анализ
- Проверка DNS без внешних API
- Анализ NS-серверов, SOA-записей
- Проверка конфигурации DNS-зоны
- Валидация SPF, DMARC, DKIM

### 🌐 Веб‑анализаторы
- `--web-version`: анализ веб‑технологий через python‑Wappalyzer (сканирует http/https, объединяет результаты и редиректы)
- `--web-test`: анализ через Wappalyzer Next (CLI + браузерная эмуляция) с более точными отпечатками
- Определение CMS, фреймворков, серверов. Генерация HTML‑отчетов

### 🛡️ HTTP Security Headers
- `--header`: проверка security‑заголовков (HSTS, CSP, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy, Permissions‑Policy, COOP/COEP/CORP, X‑XSS‑Protection)
- Консольная таблица, объединённые находки по http/https без дублей, цветовой HTML‑отчёт (missing/warning/passed)

### 🌍 Сетевая разведка
- Проверка IP-адресов через InternetDB (Shodan)
- Анализ открытых портов и сервисов
- Информация о геолокации и организации

## Установка

Вариант 1 (рекомендуется, системный PATH):
```bash
pipx install .
# После установки команда доступна как:
asm --help
```

Вариант 2 (локально):
```bash
python -m venv .venv && . .venv/Scripts/activate  # Windows PowerShell
pip install -r requirements.txt
python asm.py --help
```

### Требования для веб‑анализаторов
- `--web-version`: использует python‑Wappalyzer (ставится из `requirements.txt`). При ошибках `pkg_resources` обновите инструменты:
  ```bash
  python -m pip install --upgrade pip setuptools wheel
  ```
- `--web-test` (Wappalyzer Next):
  - Требуется Firefox и geckodriver
  - Требуется установленный CLI `wappalyzer` (лучше глобально):
    ```bash
    pipx install wappalyzer
    # проверка
    wappalyzer --help
    ```
  - Если используете локальное окружение, убедитесь, что `wappalyzer` доступен в PATH

### Настройка API ключей
Создайте файл `.env` в корне проекта:

```env
# MXToolbox API (для --dns)
MXTOOLBOX_API_KEY=ВАШ_КЛЮЧ_ОТ_MXTOOLBOX

# InternetDB не требует API ключа (бесплатный сервис)
```

## Использование

### Подготовка целей
Создайте файл `targets.txt` с целями (по одному на строку):

```txt
# Домены для DNS и веб-анализа
example.com
google.com
github.com

# IP-адреса для сетевой разведки
8.8.8.8
1.1.1.1
```

### DNS-анализ через MXToolbox API

```bash
# Базовый анализ
python asm.py --dns -f targets.txt

# С сохранением JSON ответов
python asm.py --dns -f targets.txt --json

# С генерацией HTML-отчета
python asm.py --dns -f targets.txt --html
```

### Ручной DNS-анализ (без API)

```bash
# Базовый анализ из файла
python asm.py --dns-manual -f targets.txt

# Базовый анализ с прямой передачей домена
python asm.py --dns-manual example.com

# С генерацией HTML-отчета
python asm.py --dns-manual -f targets.txt --html
```

**Проверяемые параметры:**
- Количество и доступность NS-серверов
- Авторитативность DNS-серверов
- Конфигурация SOA-записей
- SPF, DMARC, DKIM записи
- Географическое распределение NS-серверов
- Проверка открытых рекурсивных DNS

### Веб‑анализаторы

```bash
# Комбинированный анализ (из файла или напрямую)
python asm.py --web -f targets.txt
python asm.py --web example.com

# Только анализ технологий (python‑Wappalyzer)
python asm.py --web-version -f targets.txt
python asm.py --web-version example.com

# С генерацией HTML-отчетов
python asm.py --web -f targets.txt --html
python asm.py --web-version -f targets.txt --html

# Анализ Wappalyzer Next (требует wappalyzer, Firefox, geckodriver)
python asm.py --web-test -f targets.txt
python asm.py --web-test example.com --html
```

### 📦 Анализ уязвимостей и EOL по веб-отчёту

Использует JSON из веб-модуля и обогащает его данными об уязвимостях (NVD) и статусе поддержки/окончания жизни (endoflife.date).

```bash
# Обогащение с сохранением JSON и CSV
python asm.py --vuln -i reports/web_analyzer_report_YYYYMMDD_HHMMSS.json \
  --json-out reports/web_enriched.json --csv-out reports/web_enriched.csv

# Можно указать API ключ NVD для бОльших лимитов
python asm.py --vuln -i reports/web_analyzer_report_*.json --nvd-api-key YOUR_KEY

# Если выходные пути не указаны, будет выведена краткая сводка в консоль
python asm.py --vuln -i reports/web_analyzer_report_*.json
```

Источник данных:
- CVE: NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
- EOL: `https://endoflife.date/api/<product>.json`


**Определяемые технологии:**
- Веб-серверы (Apache, Nginx, IIS)
- CMS (WordPress, Drupal, Joomla)
- Фреймворки (Laravel, Django, Rails)
- Языки программирования
- Базы данных
- CDN и прокси-серверы

### Сетевая разведка IP-адресов

```bash
# Базовый анализ (из файла или напрямую)
python asm.py --network -f targets.txt
python asm.py --network 8.8.8.8 1.1.1.1

# С сохранением JSON ответов
python asm.py --network -f targets.txt --json

# С генерацией HTML-отчета
python asm.py --network -f targets.txt --html
```

### 🔐 Проверка TLS/SSL сертификатов

Проверяет поддерживаемые версии TLS (1.0/1.1/1.2/1.3) и срок действия сертификата (предупреждение, если истекает в течение 30 дней; ошибка, если просрочен). Формирует консольный вывод, JSON и/или HTML.

```bash
# Базовая проверка сертификатов (из файла или напрямую)
python asm.py --cert -f targets.txt
python asm.py --cert example.com github.com

# С HTML и JSON отчётами
python asm.py --cert -f targets.txt --html --json
```

**Получаемая информация:**
- Открытые порты и сервисы
- Географическое расположение
- Информация об организации
- Технические детали

### ⚠️ Подсказки и устранение проблем
- `python‑Wappalyzer`: ошибка `No module named 'pkg_resources'` — обновите `setuptools` (`python -m pip install --upgrade pip setuptools wheel`)
- `wappalyzer` (Next): убедитесь, что установлен `wappalyzer` и доступен в PATH, а также установлены Firefox и geckodriver
- Сети/SSL: при проблемах с доступом к сайту проверьте прокси/файрвол

## Запуск из PATH (pipx)
После `pipx install .` команда будет доступна как `asm` из любого места:
```bash
asm --help
asm --dns -f targets.txt --html
asm --web-test example.com --html
asm --header example.com --html
```

