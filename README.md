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
- Анализ веб-технологий через WhatWeb
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
Для работы модуля `--web` требуется установленный WhatWeb:
- **Windows**: Скачать с [GitHub WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- **Linux/macOS**: `sudo apt install whatweb` или `brew install whatweb`

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
# Базовый анализ
python asm.py --dns-manual -f targets.txt

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
# Базовый анализ
python asm.py --web -f targets.txt

# С генерацией HTML-отчета
python asm.py --web -f targets.txt --html
```

**Определяемые технологии:**
- Веб-серверы (Apache, Nginx, IIS)
- CMS (WordPress, Drupal, Joomla)
- Фреймворки (Laravel, Django, Rails)
- Языки программирования
- Базы данных
- CDN и прокси-серверы

### Сетевая разведка IP-адресов

```bash
# Базовый анализ
python asm.py --network -f targets.txt

# С сохранением JSON ответов
python asm.py --network -f targets.txt --json

# С генерацией HTML-отчета
python asm.py --network -f targets.txt --html
```

**Получаемая информация:**
- Открытые порты и сервисы
- Географическое расположение
- Информация об организации
- Технические детали

## Структура проекта

```
ASM/
├── asm.py                 # Главный файл приложения
├── modules/               # Модули анализа
│   ├── mxtoolbox_dns.py  # DNS-анализ через MXToolbox API
│   ├── dns_manual.py     # Ручной DNS-анализ
│   ├── web_analyzer.py   # Веб-анализатор
│   ├── network.py        # Сетевая разведка
│   └── reporters.py      # Генерация HTML-отчетов
├── utils/                 # Утилиты
│   └── target_loader.py  # Загрузка целей из файла
├── reports/               # Генерируемые отчеты
├── targets.txt            # Файл с целями
└── requirements.txt       # Зависимости Python
```

## Форматы отчетов

### Консольный вывод
Все модули выводят результаты в консоль в табличном формате с цветовой индикацией:
- 🟢 **Passed** - проверка пройдена успешно
- 🟡 **Warning** - предупреждение
- 🔴 **Failed** - проверка не пройдена

### HTML-отчеты
Генерируются в папку `reports/` с временными метками:
- `dns_manual_report_YYYYMMDD_HHMMSS.html`
- `mxtoolbox_report_YYYYMMDD_HHMMSS.html`
- `web_analyzer_report_YYYYMMDD_HHMMSS.html`
- `internetdb_network_report_YYYYMMDD_HHMMSS.html`

### JSON-ответы
Сохраняются в папку `reports/` для дальнейшего анализа:
- `dns_YYYYMMDD_HHMMSS.json`
- `network_YYYYMMDD_HHMMSS.json`

## Примеры использования

### Анализ домена компании
```bash
# Создаем файл с доменами
echo "company.com" > targets.txt
echo "www.company.com" >> targets.txt

# Запускаем полный DNS-анализ
python asm.py --dns-manual -f targets.txt --html

# Анализируем веб-технологии
python asm.py --web -f targets.txt --html
```

### Сетевая разведка
```bash
# Создаем файл с IP-адресами
echo "192.168.1.1" > targets.txt
echo "10.0.0.1" >> targets.txt

# Запускаем сетевую разведку
python asm.py --network -f targets.txt --html
```

## Устранение неполадок

### Проблемы с DNS-запросами
- Убедитесь, что интернет-соединение стабильно
- Проверьте настройки файрвола
- При зависании используйте Ctrl+C для прерывания

### Ошибки WhatWeb
- Убедитесь, что WhatWeb установлен и доступен в PATH
- Проверьте права доступа к исполняемому файлу

### Проблемы с API
- Проверьте правильность API ключей в `.env`
- Убедитесь, что лимиты API не превышены

## Зависимости

- **requests** - HTTP-запросы
- **python-dotenv** - загрузка переменных окружения
- **colorama** - цветной вывод в консоль
- **tabulate** - табличное форматирование
- **publicsuffix2** - работа с публичными суффиксами доменов
- **dnspython** - DNS-запросы

## Лицензия

Проект предназначен для образовательных целей и этичного тестирования безопасности.

## Поддержка

При возникновении проблем:
1. Проверьте логи в консоли
2. Убедитесь в корректности входных данных
3. Проверьте доступность внешних сервисов
4. Убедитесь в установке всех зависимостей
