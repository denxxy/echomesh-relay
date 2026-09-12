# Инструкция по установке, развертыванию и настройке EchoMesh Relay (`echomesh-relay`)

В данном руководстве подробно описан процесс сборки, настройки и эксплуатации высокопроизводительного узла ретрансляции **`echomesh-relay`** на серверах под управлением Linux (Ubuntu / Debian / CentOS), macOS и Windows.

---

## 1. Системные требования

- **Операционная система:** Linux (рекомендуется для продакшн-серверов: Ubuntu 22.04/24.04 LTS, Debian 12), macOS 13+, Windows Server 2019/2022.
- **Архитектура:** `x86_64` или `arm64`.
- **Минимальные ресурсы:** 1 vCPU, 512 MB RAM, 10 GB диска.
- **Инструменты (один из вариантов):**
  - **Вариант A (Native):** [Rust](https://rustup.rs/) (версия 1.80 или новее) + компилятор C (`build-essential` или `clang`).
  - **Вариант B (Docker):** [Docker Engine](https://docs.docker.com/engine/install/) + Docker Compose.

---

## 2. Подготовка сервера (Linux Ubuntu / Debian)

Обновите пакеты системы и установите необходимые системные утилиты:

```bash
sudo apt update && sudo apt install -y build-essential curl git pkg-config libssl-dev
```

Установите компилятор Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

---

## 3. Клонирование репозитория

```bash
git clone https://github.com/denxxy/echomesh-relay.git
cd echomesh-relay
```

---

## 4. Сборка и локальный запуск

### Релизная сборка бинарника:
```bash
cargo build --release
```
Бинарный исполняемый файл будет скомпилирован с оптимизациями (LTO, единый блок генерации кода) и сохранен в:
`target/release/echomesh-relay`

### Просмотр и генерация учетных данных:
Релей использует криптографический протокол Noise NK и маскировку под TLS 1.3 ClientHello (Pseudo-TLS).

Для просмотра публичного ключа и секретного токена используйте флаги CLI:
```bash
# Просмотр публичного ключа релея (Base64)
./target/release/echomesh-relay --show-public-key

# Просмотр полного JSON-конфига (ключ + токен)
./target/release/echomesh-relay --show-credentials
```

### Запуск узла:
```bash
# Прямой запуск с прослушиванием 0.0.0.0:8443
./target/release/echomesh-relay
```

---

## 5. Развертывание в Docker

В репозитории подготовлен оптимизированный мультистейдж `Dockerfile`:

### 1. Сборка Docker-образа:
```bash
docker build -t echomesh-relay:latest .
```

### 2. Запуск контейнера:
```bash
docker run -d \
  --name echomesh-relay \
  --restart always \
  -p 8443:8443 \
  -v /opt/echomesh/data:/etc/echomesh \
  -e ECHOMESH_BIND_ADDR="0.0.0.0:8443" \
  -e ECHOMESH_FALLBACK_TARGET="cloudflare.com:443" \
  echomesh-relay:latest
```

---

## 6. Настройка системной службы `systemd` (Production Linux)

Для автоматического перезапуска узла при сбоях и старте сервера рекомендуется настроить `systemd`:

1. Скопируйте исполняемый файл:
   ```bash
   sudo cp target/release/echomesh-relay /usr/local/bin/
   sudo chmod +x /usr/local/bin/echomesh-relay
   ```

2. Создайте системную директорию для хранения ключей:
   ```bash
   sudo mkdir -p /etc/echomesh
   ```

3. Создайте файл сервиса `/etc/systemd/system/echomesh-relay.service`:
   ```ini
   [Unit]
   Description=EchoMesh High-Performance Stateless Relay Proxy
   After=network.target network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/etc/echomesh
   ExecStart=/usr/local/bin/echomesh-relay --key-file /etc/echomesh/relay.key
   Restart=always
   RestartSec=3
   LimitNOFILE=65535
   Environment=RUST_LOG=info
   Environment=ECHOMESH_BIND_ADDR=0.0.0.0:8443
   Environment=ECHOMESH_FALLBACK_TARGET=cloudflare.com:443

   [Install]
   WantedBy=multi-user.target
   ```

4. Активируйте и запустите службу:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable echomesh-relay
   sudo systemctl start echomesh-relay
   ```

5. Проверьте статус службы и журналы:
   ```bash
   sudo systemctl status echomesh-relay
   sudo journalctl -u echomesh-relay -f
   ```

---

## 7. Конфигурация через переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `ECHOMESH_BIND_ADDR` | `0.0.0.0:8443` | IP-адрес и порт для прослушивания входящих соединений |
| `ECHOMESH_FALLBACK_TARGET` | `cloudflare.com:443` | Целевой сайт для скрытого проксирования неавторизованных сканеров DPI |
| `ECHOMESH_MAX_CONNECTIONS` | `1024` | Максимальное количество одновременных TCP-соединений |
| `ECHOMESH_SECRET_TOKEN` | (встроенный токен) | Pre-shared секретный токен маскировки Pseudo-TLS |
| `ECHOMESH_INSECURE_NO_AUTH`| `false` | Режим отладки: отключение проверки токена (только dev) |
| `RUST_LOG` | `info` | Уровень логирования (`trace`, `debug`, `info`, `warn`, `error`) |

---

## 8. Запуск автоматических тестов

```bash
# Запуск модульных тестов
cargo test

# Запуск тестов под нагрузкой и бенчмарков
cargo bench
```
