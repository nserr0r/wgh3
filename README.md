# wgh3

**wgh3** — это полноценный VPN-сервер и клиент, инкапсулирующий протокол WireGuard внутри HTTP/3 (MASQUE) и маскирующий весь трафик под обычный веб-сайт. WireGuard работает прямо внутри wgh3 через встроенный движок **boringtun** — отдельный демон не нужен. Снаружи это выглядит как обычный HTTPS-сайт с поддержкой HTTP/3, внутри — зашифрованный туннель.

> ⚠️ **Важно:** Использование инструмента в обход законов вашей страны — на ваш страх и риск.

## Основные возможности

- **Встроенный WireGuard** через boringtun — никаких отдельных WG-демонов, всё в одном процессе.
- **Встроенная генерация ключей** — `wgh3 keygen` и `wgh3 psk`, без зависимости от `wireguard-tools`.
- **MASQUE CONNECT-UDP (RFC 9298)** — пакеты упаковываются в HTTP/3 datagrams, неотличимы от обычного HTTPS.
- **Маскировка как у trojan-go** — TCP/443 и UDP/443 на одном порту, один TLS-сертификат, один SNI. Левые запросы прозрачно проксируются в HTTP-бэкенд.
- **Активная защита от DPI** — на любой active probe (`curl https://...`) сервер отдаёт настоящий ответ от бэкенда, а не закрывает соединение.
- **Multi-client** — один сервер обслуживает любое число клиентов, каждый со своим WG-ключом и подсетью. Идентификация peer'ов через MAC1-prefilter работает в ~50× быстрее полного decapsulate.
- **Автоматический реконнект** — клиент сам восстанавливает соединение при обрыве сети с экспоненциальным backoff.
- **Авто-маршруты с fwmark** — wgh3 сам поднимает policy routing через свою таблицу, корректно обходит трафик к серверу даже при смене gateway.
- **Хуки в стиле wg-quick** — `pre_up` / `post_up` / `pre_down` / `post_down` команды в конфиге.
- **Управление DNS** — опциональная подмена `/etc/resolv.conf` с автоматическим бэкапом и восстановлением.
- **Structured logging** через `tracing` — управляется переменной `RUST_LOG`, логи journalctl-friendly, поля доступны для grep.
- **Поддержка Let's Encrypt и self-signed** — настоящий домен или pinning по SHA-256 fingerprint.
- **IPv4 и IPv6** — оба стека из коробки.
- **Чистый Rust** — никаких go-runtime, минимум зависимостей.
- **Готовый systemd unit** — с sandbox-ограничениями, `CAP_NET_BIND_SERVICE` и `CAP_NET_ADMIN`.
- **Автоматические sysctl-настройки** — UDP-буферы для high-throughput устанавливаются при установке пакета.

## Архитектура

```
Клиент:  TUN (10.0.0.2) -> boringtun encrypt -> QUIC/H3 datagram -> сервер
Сервер:  UDP/443 -> wgh3 -> boringtun decrypt -> TUN (10.0.0.1) -> ядро
         TCP/443 -> wgh3 -> TLS -> HTTP/1.1 -> backend (nginx/Caddy/Apache/...)
```

Каждый WireGuard-пакет инкапсулируется в HTTP/3 datagram внутри QUIC-соединения. Это не туннель «WireGuard через UDP-обёртку», а полноценная двойная инкапсуляция: WG-фрейм становится payload'ом для HTTP/3 datagram и шифруется ещё раз TLS-слоем QUIC.

Сам WireGuard-протокол реализован прямо в wgh3 через библиотеку **boringtun** от Cloudflare. Отдельный `wireguard-tools` или `wg-quick` на сервере **не нужен** — wgh3 сам создаёт TUN-интерфейс, обрабатывает handshake, шифрует и расшифровывает пакеты.

Любой не-MASQUE трафик (включая active probes от DPI и сканеров) идёт в HTTP-бэкенд как обычный reverse proxy. В качестве бэкенда подойдёт любой HTTP-сервер: nginx, Caddy, Apache, lighttpd, Go-сервер, Python/Node.js приложение — wgh3 говорит с ним по обычному HTTP/1.1 без TLS.

## Установка

### Из исходников

```
git clone https://github.com/nserr0r/wgh3
cd wgh3
make build
sudo make install
sudo sysctl --system
```

Бинарь устанавливается в `/usr/bin/wgh3`, systemd unit в `/usr/lib/systemd/system/wgh3.service`, sysctl-настройки в `/usr/lib/sysctl.d/60-wgh3.conf`.

### Зависимости

- Rust 1.88+
- cmake (для сборки QUIC-библиотеки)
- Любой HTTP-сервер для маскировки (опционально)
- Let's Encrypt сертификат (рекомендуется) или self-signed с pinning

## Генерация ключей

wgh3 умеет генерировать ключи сам — никаких сторонних утилит:

```
wgh3 keygen
```

Выведет готовые строки для конфига:

```
private_key = "AKMxYz..."
public_key  = "Bk7Lp9..."
```

Сгенерируйте отдельно для сервера и для каждого клиента. Опционально можно создать pre-shared key для дополнительного слоя защиты:

```
wgh3 psk
```

Если у вас уже есть приватный ключ от обычного WireGuard и нужно получить публичный:

```
echo "приватный-ключ" | wgh3 pubkey
```

Полностью совместимо с ключами из стандартного `wireguard-tools` — алгоритм X25519 одинаковый.

## Конфигурация

### Сервер (`/etc/wgh3/config.toml`)

```toml
mode = "server"
token = "длинный-секрет"
listen = "0.0.0.0:443"

[wireguard]
private_key = "СОДЕРЖИМОЕ-server.key"

[network]
tun_name = "wgh3"
address = "10.0.0.1/24"
mtu = 1380

[tls]
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"

[fallback]
upstream = "127.0.0.1:3000"
listen_tcp = "0.0.0.0:443"

[[peer]]
public_key = "СОДЕРЖИМОЕ-client1.pub"
allowed_ips = ["10.0.0.2/32"]

[[peer]]
public_key = "СОДЕРЖИМОЕ-client2.pub"
allowed_ips = ["10.0.0.3/32"]
```

Каждый клиент описывается отдельной секцией `[[peer]]`. Подсети в `allowed_ips` не должны пересекаться — wgh3 проверяет это при старте и откажется запускаться, если они конфликтуют.

### Клиент (`/etc/wgh3/config.toml`)

```toml
mode = "client"
token = "длинный-секрет"

server = "1.2.3.4:443"
server_name = "example.com"

[wireguard]
private_key = "СОДЕРЖИМОЕ-client.key"
peer_public_key = "СОДЕРЖИМОЕ-server.pub"
peer_allowed_ips = ["0.0.0.0/0"]

[network]
tun_name = "wgh3"
address = "10.0.0.2/24"
mtu = 1380

# Опционально - автоматическая маршрутизация:
# auto_route = true
# dns = ["1.1.1.1", "8.8.8.8"]
```

Опционально для self-signed:

```toml
pin_sha256 = "ab:cd:ef:..."
```

### HTTP-бэкенд

Любой HTTP-сервер, слушающий на `127.0.0.1:3000` (или другом порту, указанном в `fallback.upstream`) **без TLS** — TLS терминирует сам wgh3.

Пример с nginx:

```nginx
server {
    listen 127.0.0.1:3000;
    server_name example.com;

    root /var/www/example.com;
    index index.html;
}
```

Пример с Caddy:

```caddyfile
:3000 {
    bind 127.0.0.1
    root * /var/www/example.com
    file_server
}
```

Пример с Python (для теста):

```
cd /var/www/example.com
python3 -m http.server 3000 --bind 127.0.0.1
```

## Маршрутизация на сервере

Чтобы клиенты могли ходить через сервер в интернет, нужны IP forwarding и NAT. Это можно сделать вручную или через хуки в конфиге сервера. Хуки запустятся автоматически при старте wgh3 и откатятся при остановке.

В `[network]` секции конфига сервера:

```toml
post_up = [
    "sysctl -w net.ipv4.ip_forward=1",
    "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
    "iptables -A FORWARD -i %i -j ACCEPT",
    "iptables -A FORWARD -o %i -j ACCEPT",
]
post_down = [
    "iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
    "iptables -D FORWARD -i %i -j ACCEPT",
    "iptables -D FORWARD -o %i -j ACCEPT",
]
```

Замените `eth0` на имя вашего внешнего интерфейса. `%i` подставится именем TUN-интерфейса.

Альтернативно — можно настроить вручную:

```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Или через nftables:

```
sudo nft add table ip nat
sudo nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
sudo nft add rule ip nat postrouting oifname "eth0" masquerade
```

Чтобы IP forwarding пережил ребут (если не используете `post_up`):

```
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.d/99-forward.conf
```

## Сертификаты Let's Encrypt

При использовании Let's Encrypt сертификат обновляется раз в 60 дней. После каждого renew нужно перезапустить wgh3, чтобы он подхватил новые файлы. Создайте deploy-hook:

```
sudo tee /etc/letsencrypt/renewal-hooks/deploy/wgh3.sh <<'EOF'
#!/bin/sh
systemctl reload-or-restart wgh3
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/wgh3.sh
```

certbot будет автоматически вызывать его после успешного обновления сертификата.

## Маршрутизация на клиенте

wgh3 может управлять маршрутами автоматически. Это опционально — если ничего не задать в `[network]`, wgh3 поднимет только TUN, а маршруты пользователь настроит сам.

### Авто-маршруты

```toml
[network]
auto_route = true
```

Этого достаточно. wgh3 сам:

- Создаст отдельную routing-таблицу `51821` и положит в неё default через TUN
- Добавит `ip rule` с fwmark `51821` который выводит свой собственный QUIC-трафик мимо туннеля (через основную таблицу)
- Поставит `SO_MARK = 51821` на свой UDP-сокет, чтобы это правило сработало

Это переживает смену gateway (мобильный интернет, переключение Wi-Fi/Ethernet) — в отличие от подхода с фиксированным exclude-маршрутом.

### Тонкая настройка

```toml
[network]
auto_route = true
table = 51821              # routing-таблица: число | "main" | "off" | "auto"
fwmark = 51821             # метка пакетов wgh3
dns = ["1.1.1.1", "8.8.8.8"]
```

Значения `table` и `fwmark` по умолчанию — `51821`. Это **отличается** от стандартного wg-quick (`51820`), чтобы wgh3 мог работать рядом с обычным WireGuard на одной машине без конфликтов. Если поднимаете несколько wgh3 туннелей на одном хосте — задайте уникальные значения вручную.

### Хуки в стиле wg-quick

```toml
[network]
pre_up = ["команда до создания TUN"]
post_up = ["команда после поднятия туннеля"]
pre_down = ["команда до остановки"]
post_down = ["команда после остановки"]
```

В командах подставляется `%i` — имя TUN-интерфейса. Команды выполняются через `sh -c` от рута. Если команда вернула ненулевой код — wgh3 продолжает работу (как у wg-quick).

### Без auto_route

Если `auto_route` не указан или `false`, wgh3 не трогает маршруты. После запуска направьте трафик в TUN сами:

```
sudo ip route add default dev wgh3
sudo ip route add 1.2.3.4 via $(ip route show default | awk '{print $3; exit}')
```

Где `1.2.3.4` — IP вашего wgh3-сервера. Без второй команды получится петля.

### Аварийная очистка

Если процесс убили `kill -9`, маршруты остаются в системе. Очистить:

```
sudo wgh3 cleanup wgh3
```

Где `wgh3` — имя TUN-интерфейса. systemd-юнит делает это автоматически через `ExecStopPost`.

## Запуск

### Через systemd

```
sudo systemctl enable --now wgh3
sudo systemctl status wgh3
journalctl -u wgh3 -f
```

### Вручную

```
sudo wgh3 /etc/wgh3/config.toml
```

### Утилитные команды

```
wgh3 keygen                   # сгенерировать пару ключей
wgh3 psk                      # сгенерировать pre-shared key
wgh3 pubkey                   # получить публичный ключ из приватного (читает stdin)
wgh3 cleanup <tun_name>       # очистить маршруты после kill -9
```

## Логирование

wgh3 использует `tracing` для structured-логов. Уровень управляется через `RUST_LOG`:

```
RUST_LOG=wgh3=info       # дефолт: подключения peer'ов, старт компонентов, важные события
RUST_LOG=wgh3=warn       # только предупреждения и ошибки
RUST_LOG=wgh3=debug      # детали handshake, dropped packets, ошибки decap
```

Через systemd:

```
sudo systemctl edit wgh3
```

И добавить:

```
[Service]
Environment=RUST_LOG=wgh3=debug
```

Логи попадают в journalctl со структурными полями. Поиск по полю:

```
journalctl -u wgh3 | grep 'peer=AbCdEfGh'
journalctl -u wgh3 -p warning            # только warn и выше
journalctl -u wgh3 --since '5 min ago' -f
```

## Параметры конфигурации

| Параметр | Описание | По умолчанию |
| --- | --- | --- |
| `mode` | Режим работы: `server` или `client` | — |
| `token` | Общий пароль для аутентификации MASQUE | — |
| `listen` | UDP-адрес для прослушивания QUIC (только сервер) | — |
| `server` | Адрес сервера (только клиент) | — |
| `server_name` | SNI/домен для TLS | — |
| `pin_sha256` | SHA-256 отпечаток сертификата для pinning | — |
| `insecure` | Отключить проверку сертификата (только тесты) | `false` |
| `wireguard.private_key` | Приватный WG-ключ (base64) | — |
| `wireguard.peer_public_key` | Публичный ключ сервера (только клиент) | — |
| `wireguard.peer_allowed_ips` | Маршруты пира (только клиент, для auto_route) | `[]` |
| `wireguard.persistent_keepalive` | Интервал keepalive в секундах | `25` |
| `network.tun_name` | Имя TUN-интерфейса | `wgh3` |
| `network.address` | IP-адрес TUN с маской подсети | — |
| `network.mtu` | MTU TUN-интерфейса | `1380` |
| `network.auto_route` | Автоматически настраивать маршруты + fwmark | `false` |
| `network.table` | Routing-таблица: число / `main` / `off` / `auto` | `auto` |
| `network.fwmark` | SO_MARK на сокете wgh3 | `51821` (если auto_route) |
| `network.dns` | DNS-серверы для туннеля | `[]` |
| `network.pre_up` | Команды до создания TUN | `[]` |
| `network.post_up` | Команды после поднятия туннеля | `[]` |
| `network.pre_down` | Команды до остановки | `[]` |
| `network.post_down` | Команды после остановки | `[]` |
| `tls.cert` / `tls.key` | Пути к TLS-сертификату и ключу (сервер) | — |
| `fallback.upstream` | Адрес HTTP-бэкенда | — |
| `fallback.listen_tcp` | TCP-порт для маскировки | — |
| `[[peer]].public_key` | Публичный ключ клиента (только сервер) | — |
| `[[peer]].allowed_ips` | Подсети клиента (только сервер) | — |
| `[[peer]].preshared_key` | Опциональный pre-shared key | — |

## Как это работает

При попытке DPI определить трафик по UDP/443 он видит:

- Корректный QUIC handshake
- Валидный TLS-сертификат от Let's Encrypt
- HTTP/3 ALPN
- Реальный SNI вашего домена

При active probe через TCP/443 (`curl`, сканер, бот):

- TLS-handshake проходит на том же сертификате
- HTTP/1.1 запрос проксируется в HTTP-бэкенд
- Возвращается реальный контент сайта

Снаружи это выглядит как обычный сайт с поддержкой HTTP/3. Внутри — туннель для WireGuard.

## Производительность

В сравнении с голым WireGuard:

- Накладные расходы шифрования удваиваются (WG-AEAD внутри QUIC-AEAD)
- Добавляется overhead HTTP/3 фрейминга
- Реальная скорость составляет 50-70% от голого WG в зависимости от CPU и сети

В обмен получаете **полную маскировку** под обычный HTTPS-трафик — DPI не отличает wgh3 от посещения сайта в браузере.

## Ограничения

- **Cloudflare proxy не поддерживается** — CF не пробрасывает CONNECT-UDP до origin. Используйте DNS-only режим.
- **Не обходит блокировку UDP целиком** — если в сети режется весь UDP/443, инструмент не поможет.
- **Зависит от качества SNI** — маскировка работает только с реальным доменом и валидным сертификатом.
- **DNS не управляется при systemd-resolved** — если `/etc/resolv.conf` симлинк, опция `dns` пропускается. Настраивайте через `resolvectl` или хук `post_up`.

## Безопасность

- Аутентификация по shared secret (`token`). 
- WireGuard-ключи на тех же принципах, что в стандартном WG.
- TLS терминируется в самом wgh3, ключи бэкенда не нужны.
- systemd unit идёт с sandbox: `NoNewPrivileges`, `ProtectKernelModules`, `RestrictRealtime`, `LockPersonality` и так далее.
- При пересечении подсетей в `allowed_ips` сервер откажется запускаться.
- **Конфиг должен быть защищён правами `600 root:root`** — он содержит приватные ключи WG и команды хуков, которые выполняются от рута.

## Лицензия

Этот проект лицензирован под Apache License 2.0. Вы можете свободно использовать, распространять и модифицировать в соответствии с условиями лицензии.

Для получения подробной информации смотрите файл `LICENSE` или посетите [сайт Apache](https://www.apache.org/licenses/LICENSE-2.0).

## Контакт

**Автор**: NSerr0R  
**Email**: nserr0r@gmail.com
