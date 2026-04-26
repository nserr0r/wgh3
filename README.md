# wgh3

**wgh3** — это туннель для WireGuard поверх HTTP/3 (MASQUE), маскирующий VPN-трафик под обычный веб-сайт. На стороне сервера разворачивается полноценный HTTPS-фронт: WireGuard-туннель идёт по UDP/443 через CONNECT-UDP, а весь остальной трафик прозрачно проксируется на любой HTTP-сервер — как у trojan-go, только современнее.

> ⚠️ **Важно:** Использование инструмента в обход законов вашей страны — на ваш страх и риск.

## Основные возможности

- **MASQUE CONNECT-UDP (RFC 9298)**: WireGuard-пакеты упаковываются в HTTP/3 datagrams, неотличимы от обычного HTTPS-трафика.
- **Маскировка как у trojan-go**: TCP/443 и UDP/443 на одном порту, один TLS-сертификат, один SNI. Левые запросы прозрачно проксируются в HTTP-бэкенд.
- **Активная защита от DPI**: на любой active probe (`curl https://...`) сервер отдаёт настоящий ответ от бэкенда, а не закрывает соединение.
- **Поддержка Let's Encrypt и self-signed**: можно работать с настоящим доменом или с pinning по SHA-256 fingerprint.
- **IPv4 и IPv6**: оба стека из коробки.
- **Минимум зависимостей**: чистый Rust, никаких go-runtime, никаких внешних сервисов.
- **Готовый systemd unit**: с sandbox-ограничениями и `CAP_NET_BIND_SERVICE`.

## Архитектура

```
Клиент:  WireGuard → wgh3-client (127.0.0.1:51820) → QUIC/H3 → сервер
Сервер:  UDP/443 → wgh3 → CONNECT-UDP → WireGuard
         TCP/443 → wgh3 → TLS → HTTP/1.1 → backend (nginx/Caddy/Apache/...)
```

WireGuard-клиент думает, что коннектится к локальному endpoint. wgh3-клиент заворачивает пакеты в QUIC и отправляет на сервер. Сервер распаковывает и отдаёт WireGuard-демону. Любой не-MASQUE трафик (включая active probes от DPI) идёт в HTTP-бэкенд как обычный reverse proxy.

В качестве бэкенда подойдёт любой HTTP-сервер: nginx, Caddy, Apache, lighttpd, Go-сервер, Python/Node.js приложение — wgh3 говорит с ним по обычному HTTP/1.1 без TLS.

## Установка

### Из исходников

```
git clone https://github.com/nserr0r/wgh3
cd wgh3
make build
sudo make install
```

Бинарь установится в `/usr/bin/wgh3`.

### Зависимости

- Rust 1.85+
- Любой HTTP-сервер для маскировки на стороне сервера (опционально)
- WireGuard
- Let's Encrypt сертификат (рекомендуется) или self-signed с pinning

## Конфигурация

### Сервер (`/etc/wgh3/config.toml`)

```toml
mode = "server"
token = "пароль"
listen = "0.0.0.0:443"

[wireguard]
endpoint = "127.0.0.1:51820"

[tls]
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"

[fallback]
upstream = "127.0.0.1:3000"
listen_tcp = "0.0.0.0:443"
```

### Клиент (`/etc/wgh3/config.toml`)

```toml
mode = "client"
token = "пароль"
listen = "127.0.0.1:51820"
server = "1.2.3.4:443"
server_name = "example.com"
server_target = "127.0.0.1:51820"
```

Опционально для self-signed:

```toml
pin_sha256 = "ab:cd:ef:..."
```

### HTTP-бэкенд

Любой HTTP-сервер, слушающий на `127.0.0.1:3000` (или другом порту, указанном в `fallback.upstream`) **без TLS** — TLS терминирует сам wgh3.

#### Пример с nginx

```nginx
server {
    listen 127.0.0.1:3000;
    server_name example.com;

    root /var/www/example.com;
    index index.html;
}
```

#### Пример с Caddy

```caddyfile
:8080 {
    bind 127.0.0.1
    root * /var/www/example.com
    file_server
}
```

#### Пример с Python (для теста)

```
cd /var/www/example.com
python3 -m http.server 3000 --bind 127.0.0.1
```

### WireGuard клиент

```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.2/32

[Peer]
PublicKey = ...
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

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

## Параметры конфигурации

| Параметр | Описание | По умолчанию |
| --- | --- | --- |
| `mode` | Режим работы: `server` или `client` | — |
| `token` | Общий пароль для аутентификации MASQUE | — |
| `listen` | Адрес для прослушивания | — |
| `server` | Адрес сервера (только клиент) | — |
| `server_name` | SNI/домен для TLS | — |
| `server_target` | Адрес WG-демона на стороне сервера | — |
| `pin_sha256` | SHA-256 отпечаток сертификата для pinning | — |
| `insecure` | Отключить проверку сертификата (только тесты) | `false` |
| `wireguard.endpoint` | Адрес WG-демона (только сервер) | — |
| `tls.cert` / `tls.key` | Пути к TLS-сертификату и ключу (сервер) | — |
| `fallback.upstream` | Адрес HTTP-бэкенда для проксирования | — |
| `fallback.listen_tcp` | TCP-порт для маскировки (обычно `0.0.0.0:443`) | — |

## Как это работает

При попытке DPI определить что за трафик идёт по UDP/443 он видит:

- Корректный QUIC handshake
- Валидный TLS-сертификат от Let's Encrypt
- HTTP/3 ALPN
- Реальный SNI вашего домена

При active probe через TCP/443 (`curl`, сканер, бот):

- TLS-handshake проходит на том же сертификате
- HTTP/1.1 запрос проксируется в HTTP-бэкенд
- Возвращается реальный контент (статичный сайт, лендинг, что угодно)

Снаружи это выглядит как обычный сайт с поддержкой HTTP/3. Внутри — туннель для WireGuard.

## Ограничения

- **Cloudflare proxy не поддерживается**: CF не пробрасывает CONNECT-UDP до origin. Используйте DNS-only режим.
- **Один MASQUE-стрим = один WG-пир**: масштабирование на несколько клиентов идёт через отдельные QUIC-соединения.
- **Не обходит блокировку UDP целиком**: если в сети режется весь UDP/443, инструмент не поможет.
- **Зависит от качества SNI**: маскировка работает только с реальным доменом и валидным сертификатом.

## Безопасность

- Аутентификация по shared secret (`token`). 
- TLS terminates в самом wgh3, ключи бэкенда не нужны.
- Сертификаты Let's Encrypt подхватываются через ACL и certbot deploy hook.
- systemd unit идёт с sandbox: `NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies` и так далее.

## Лицензия

Этот проект лицензирован под Apache License 2.0. Вы можете свободно использовать, распространять и модифицировать в соответствии с условиями лицензии.

Для получения подробной информации смотрите файл `LICENSE` или посетите [сайт Apache](https://www.apache.org/licenses/LICENSE-2.0).

## Контакт

**Автор**: Nserr0r  
**Email**: nserr0r@gmail.com
