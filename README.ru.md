# 🌽 CornProxy
[![License Badge](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Compatibility](https://img.shields.io/badge/python-3-brightgreen.svg)](PROJECT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

CornProxy — это локальный HTTP/SOCKS proxy-сервер с поддержкой прокси-пула, мониторингом трафика и TUI-интерфейсом.

Проект создан для изучения:

- сетевых протоколов (HTTP / SOCKS)
- работы прокси-серверов
- анализа трафика
- базовых методов DPI-обфускации

---

⚙️ Возможности

- HTTP proxy (CONNECT + обычные HTTP-запросы)
- SOCKS4 / SOCKS5 поддержка
- Локальный proxy-сервер (127.0.0.1:8888)
- Прокси-пул с ротацией
- Автозагрузка бесплатных прокси
- Проверка доступности прокси
- Статистика трафика (sent / received)
- Статистика по хостам
- Реальное время (TUI интерфейс)
- Логирование в CSV
- Экспериментальные DPI методы:
  - "random_case"
  - "noise headers"
  - "packet fragmentation (basic)"

---

🧠 Архитектура

Client (Browser / App)
        ↓
  CornProxy (Local)
        ↓
 Proxy Pool (HTTP / SOCKS)
        ↓
   Target Websites

---

📦 Установка

```
git clone https://github.com/CornVPN/cornproxy.git
cd cornproxy
pip install -r requirements.txt
```
requirements.txt

rich
pysocks
plotext
pyfiglet
colorama
requests
beautifulsoup4
lxml

---

🚀 Запуск
```
python cornproxy.py
```
---

🧩 Режимы работы

1. Manual Proxy

Один заданный прокси-сервер.

2. Proxy Pool

- загрузка списка прокси
- автоматическая проверка
- ротация рабочих прокси

3. Direct Mode

Без внешних прокси (локальное логирование трафика)

---

🎛 Управление

Клавиша| Действие
r| Reset statistics
s| Save CSV log
p| Update proxy pool
d| Toggle DPI mode
q| Quit

---

📊 Интерфейс показывает

- общий трафик (upload / download)
- скорость передачи данных
- активные соединения
- топ хостов
- график скорости
- количество рабочих прокси

---

⚠️ Ограничения

- ❌ нет UDP поддержки
- ❌ нет DNS tunneling
- ❌ анти-DPI режимы экспериментальные
- ❌ бесплатные прокси нестабильны
- ❌ не является VPN

---

🧪 Примечания

CornProxy не является VPN или инструментом гарантированного обхода блокировок.

Он работает только как:

«локальный прокси + маршрутизатор трафика через внешние прокси»

---

🧱 Use Cases

- изучение сетевых протоколов
- тестирование прокси-соединений
- мониторинг HTTP/SOCKS трафика
- учебные проекты по сетевому программированию

---

📈 Статус проекта

«⚠️ Experimental / Learning project»

Проект находится в стадии активной разработки и может содержать нестабильные функции.

---

📜 License

MIT

---

🤝 Contributing

Pull requests приветствуются.
Идеи по улучшению proxy engine, performance и DPI-обхода особенно интересны.
