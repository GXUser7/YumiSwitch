# Yumi NX (`YumiSwitch`)

Нативный автономный VPN-клиент для прошитого **Nintendo Switch** (Atmosphere CFW, Horizon OS 19.x и 20.0+), основанный на архитектуре и протоколах [Yumi](https://github.com/GXUser7/yumi).

Работает прямо на консоли без внешнего роутера или ПК: системный модуль `yumi-sysmodule` (`exefs.nsp`, TitleID `4200000000079801`) перехватывает сетевые сокеты через MITM `bsd:u` и `sfdnsres`, UI-клиент `yumi.nro` на `NanoVG + Yoga` управляет подписками, правилами и пультом с телефона, а оверлей `yumi.ovl` даёт мгновенный доступ прямо поверх YouTube и игр.

---

## Быстрая установка для друга (готовый архив)

Не нужно ничего компилировать — достаточно перенести готовые файлы на microSD-карту приставки:

1. **Скачайте архив** `YumiSwitch-v1.0.1-sd.zip` со страницы [GitHub Releases](https://github.com/GXUser7/YumiSwitch/releases/latest).
2. **Распакуйте содержимое архива в корень microSD-карты Switch** (с заменой/слиянием папок — чтобы в корне карты оказались `atmosphere/` и `switch/`):
   - `atmosphere/contents/4200000000079801/exefs.nsp` — фоновый VPN sysmodule
   - `atmosphere/contents/4200000000079801/toolbox.json` — запись **Yumi VPN** для sysmodule-менеджеров (`requires_reboot: true`)
   - `atmosphere/contents/4200000000079801/flags/boot2.flag` — автозапуск модуля при старте Switch
   - `switch/yumi/yumi.nro` — основное приложение
   - `switch/.overlays/yumi.ovl` — оверлей для **Ultrahand** / **Tesla Menu**
3. **Обязательно перезагрузите Switch** после установки, обновления файлов или переключения **Yumi VPN** в sysmodule-менеджере (`boot2.flag` запустит обновлённый модуль чисто при старте системы).
4. **Откройте приложение `Yumi NX`:**
   - Запустите любую игру/приложение, **удерживая кнопку `R`**, чтобы открыть Homebrew Menu в режиме *Title Takeover* (с полным доступом к оперативной памяти), и выберите **Yumi NX**.
   - *(Запуск из Альбома в applet-режиме ограничивает RAM и не рекомендуется.)*

> Требования: прошитый Switch с **Atmosphere CFW** (HOS 19.x или 20.0+); для оверлея `yumi.ovl` требуется установленный **Ultrahand** или **Tesla Menu (`nx-ovlloader`)**.

---

## Как добавить подписку и серверы (3 способа)

### Способ 1 — Передача с Android-приложения Yumi по QR (`yumi://pair`)
Самый удобный способ без ввода длинных ссылок с экранной клавиатуры Switch:
1. Подключите Switch и Android-смартфон к **одной Wi-Fi сети**.
2. На Switch откройте вкладку **Подписки** (`Подписки и QR`).
3. В приложении **Yumi** на телефоне выберите профиль подписки, нажмите отправку на устройство/Switch и отсканируйте QR-код с экрана приставки.
4. Передача шифруется через одноразовый `ECDH P-256 + AES-256-GCM` (`yumi-pair-v1`, QR действует 5 минут). После подтверждения подписка и серверы сразу загрузятся на Switch.

### Способ 2 — Пульт управления с телефона (`yumi://remote`)
Превращает Android Yumi в беспроводной пульт для Switch:
1. На Switch откройте **Настройки -> Пульт и система**.
2. Отсканируйте QR-код `yumi://remote` из мобильного приложения Yumi.
3. После однократного сопряжения телефон запоминает устройство (`remote_identity.json`), находит приставку в локальной сети автоматически по UDP-маяку (`47655`) и управляет туннелем по шифрованному TCP (`47654`): включение/выключение VPN, выбор узла, замер пинга, добавление/обновление/переключение подписок и изменение настроек.

### Способ 3 — Локальный файл на microSD (`import.txt`)
Если телефон не под рукой или нужно добавить подписку офлайн:
1. Создайте файл `sdmc:/config/yumi-nx/import.txt` на microSD-карте.
2. Вставьте в него одну или несколько прокси-ссылок (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` / `hy2://`, `wireguard://` / `wg://`, `socks5://`, `http://`), Base64-подписку, Xray JSON, SIP008 JSON или конфиг Clash YAML.
3. Откройте на Switch вкладку **Подписки** и нажмите **`Y`** (*Добавить из файла (SD)*).

---

## Управление и оверлей поверх игр

### В приложении `yumi.nro`
- **`L` / `R`** — переключение вкладок (*Туннель*, *Серверы*, *Подписки*, *Правила*, *Настройки*)
- **`D-Pad` / левый стик / сенсорный экран** — навигация по элементам
- **`A`** — подключить/отключить туннель, выбрать сервер или применить настройку
- **`X`** — замер задержки всех узлов (на вкладке *Серверы*) или быстрая смена режима `Global / Rules / Direct`
- **`Y`** — импорт `sdmc:/config/yumi-nx/import.txt` (на вкладке *Подписки*) или перезагрузка конфигурации sysmodule

### В оверлее `yumi.ovl` (Tesla / Ultrahand)
Откройте оверлей стандартной комбинацией **`L` + `D-Pad Вниз` + нажатие на `R-Stick`**:
- Включение/отключение VPN без выхода из YouTube или игры
- Переключение режима маршрутизации (`Global`, `Rules`, `Direct`)
- Быстрый выбор узла из списка `quick_nodes.txt`
- Индикатор состояния подключения и памяти sysmodule

---

## Возможности и поддерживаемые протоколы

- **Протоколы (9 вариантов):** `VLESS` (включая `XTLS-REALITY` и `xtls-rprx-vision`), `VMess` (AEAD + SHAKE128), `Trojan`, `Shadowsocks` (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305` и SIP022 `2022-blake3-*`), `Hysteria2` (QUIC v1 + обфускация Salamander на BLAKE2b), `WireGuard` (`Noise_IKpsk2`), `SOCKS5`, `HTTP CONNECT`, `Direct`.
- **Транспорты:** `Raw TCP`, `WebSocket`, `HTTPUpgrade`, `gRPC` (HTTP/2), `XHTTP`.
- **Обход DPI и стабильность:** подмена отпечатка `uTLS` (`Auto`, `Chrome`, `Firefox`, `Safari`, `Edge`, `iOS`, `Android`, `Random`), фрагментация `ClientHello` / TCP (`TlsHello`, `TcpSegments`), блокировка QUIC (`UDP 443`) для стабильной работы YouTube, встроенный `DNS-over-HTTPS` (DoH) с кешем и FakeIP `198.18.0.0/16`.
- **Умная маршрутизация и Split Tunneling:** режимы `Global` / `Rules` / `Direct`, приоритет `Block -> Direct -> Proxy`, пользовательские правила `CustomRules`, компиляция `rules.bin` (опционально из `geosite.dat` / `geoip.dat` в `sdmc:/config/yumi-nx/`), разделение трафика по `TitleID` установленных игр и приложений Horizon OS.
- **Инструменты диагностики:** многопоточный тест задержки (`TCP`, `TLS`, `UrlTest` с медианой), встроенный `SpeedTest` пропускной способности и проверка обновлений на GitHub Releases.

---

## Файлы конфигурации на microSD (`sdmc:/config/yumi-nx/`)

| Файл | Назначение |
| :--- | :--- |
| `settings.json` | Настройки маршрутизации, DoH, uTLS, фрагментации, `TitleID` и `CustomRules` |
| `subscriptions.json` | Список подписок, заголовки и счётчики трафика (`subscription-userinfo`) |
| `nodes.json` | Все импортированные и разобранные серверы |
| `active_node.bin` | Бинарная запись выбранного сервера для чтения sysmodule |
| `rules.bin` | Скомпилированный индекс правил маршрутизации |
| `quick_nodes.txt` | Список быстрых узлов для оверлея `yumi.ovl` |
| `import.txt` | Пользовательский файл ручного импорта подписок и ссылок |
| `remote_identity.json` | Ключ `ECDH P-256` и список доверенных телефонов для пульта |
| `geosite.dat` / `geoip.dat` | *(Опционально)* Базы v2fly для компиляции гео-правил в `rules.bin` |
| `updates/` | Временная и финальная папка атомарной загрузки обновлений |

---

## Как временно отключить или удалить

- **Отключить VPN без удаления:** нажмите **Отключить** в `Yumi NX` или в оверлее `yumi.ovl`.
- **Отключить автозапуск sysmodule:** удалите файл `atmosphere/contents/4200000000079801/flags/boot2.flag` или выключите `Yumi VPN` в менеджере sysmodule.
- **Полное удаление:** удалите папку `atmosphere/contents/4200000000079801/`, `switch/yumi/`, `switch/.overlays/yumi.ovl` и при необходимости конфиги `config/yumi-nx/`.

---

## Архитектура репозитория и сборка из исходников

- `common/` — модели (`ProxyNode`, `AppSettings`, `CustomRules`), парсер подписок и ссылок, компилятор `rules.bin`, кодеки `active_node.bin` и JSON, матричный генератор QR V1–V15, контракт IPC `yumi:ctl`.
- `core-net/` — сетевое ядро C++20 без исключений и сторонних тяжёлых зависимостей (`TLS 1.3 / XTLS-REALITY / uTLS`, `P-256 / BLAKE3 / BLAKE2b / X25519 / ChaCha20 / AES-GCM`, транспорты, все 9 диалеров, `DohResolver`, `TunnelEngine`).
- `sysmodule/` — фоновый процесс `yumi_sysmodule.nsp` (`-fno-exceptions -fno-rtti`, сборка с `--gc-sections`, лимит памяти <= 5.5 МБ для HOS 20.0+).
- `app/` — интерфейс `yumi.nro` (`NanoVG` + `Yoga`), сервисы (`HttpClient`, `PairingServer`, `RemoteServer`/`RemoteBeacon`, `LatencyTester`, `HosApps`, `SpeedTester`, `UpdateChecker`) и десктопный предпросмотр `desktop_preview.exe`.
- `overlay/` — Tesla/Ultrahand оверлей `yumi.ovl` (`libtesla`).
- `tests/` — 29 unit- и E2E-тестов (`yumi_tests.exe`).

Для самостоятельной сборки на Windows требуются **MSYS2 (`ucrt64` CMake/Ninja/MinGW, GLFW, GLEW)** и **devkitPro (`devkitA64`, `libnx`, `switch-tools`)**:

```powershell
# Сборка всех целей (Windows-тесты + Desktop-превью + Switch .nsp/.nro/.ovl) и прогон 29 тестов
.\tools\build.ps1 -Target all

# Только ПК-тесты (yumi_tests.exe) и предпросмотр UI (desktop_preview.exe)
.\tools\build.ps1 -Target desktop

# Только бинарники для Switch в папке sd_out/
.\tools\build.ps1 -Target switch
```
