# ASM - Модульное приложение для пассивной разведки

Модульное приложение для пассивной разведки доменов и IP-адресов. Включает в себя анализ DNS-записей, проверку Email Health, анализ веб-технологий и сетевую разведку.

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

### 🌐 Веб-анализатор
- Анализ веб-технологий через python-Wappalyzer (сканирует http и https)
- Определение CMS, фреймворков, серверов
- Генерация HTML-отчетов

### 🌍 Сетевая разведка
- Проверка IP-адресов через InternetDB (Shodan)
- Анализ открытых портов и сервисов
- Информация о геолокации и организации

## Установка

```bash
pip install -r requirements.txt
```

### Требования для веб-анализатора
Модуль `--web` использует python-Wappalyzer. Зависимость ставится из `requirements.txt`.

Если при запуске получите ошибку импорта `pkg_resources` (из `setuptools`), обновите инструменты установки:
```bash
python -m pip install --upgrade pip setuptools wheel
```

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

### Веб-анализатор

```bash
# Комбинированный анализ (из файла или напрямую)
python asm.py --web -f targets.txt
python asm.py --web example.com

# Только анализ технологий (как раньше --web)
python asm.py --web-version -f targets.txt
python asm.py --web-version example.com

# С генерацией HTML-отчетов
python asm.py --web -f targets.txt --html
python asm.py --web-version -f targets.txt --html
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

### Проблемы с веб-анализатором (python-Wappalyzer)
- Ошибка `No module named 'pkg_resources'`: установите/обновите `setuptools`:
  ```bash
  python -m pip install --upgrade pip setuptools wheel
  ```
- Ошибки `lxml` при установке: убедитесь, что пакет `lxml` установлен:
  ```bash
  pip install lxml
  ```
- Сети/SSL: при проблемах с доступом к сайту проверьте прокси/файрвол и повторите запуск.

