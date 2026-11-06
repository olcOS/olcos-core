<h1 align="center">olcos-core</h1>

<p align="center">
  Общее ядро приложений olcOS для iPhone и Android: туннель olcrtc, код на Go, который приложения<br>
  собирают через gomobile, и скрипты, которые ставят сервер.
</p>

> [!IMPORTANT]
> **Хотите просто установить приложение?** Здесь только исходный код ядра. Готовые файлы и пошаговая инструкция
> лежат в [главном репозитории olcOS](https://github.com/olcOS/olcos) и на [сайте](https://olcos.github.io/#download).

<p align="center">
  <a href="https://olcos.github.io">Сайт</a> ·
  <a href="https://github.com/olcOS/olcos">Инструкция</a> ·
  <a href="https://github.com/olcOS/olcos-ios">iOS</a> ·
  <a href="https://github.com/olcOS/olcos-android">Android</a> ·
  <a href="README.en.md">English</a>
</p>

## Что это

olcOS помогает обойти белые списки мобильного интернета: телефон и ваш сервер заходят в один видеозвонок (VK
Звонки, Яндекс Телемост, SaluteJazz, МТС Линк, Jitsi) и передают трафик внутри него. Всё, что для этого не зависит от
конкретного телефона, лежит здесь. Приложения [для iOS](https://github.com/olcOS/olcos-ios) и
[для Android](https://github.com/olcOS/olcos-android) подключают этот репозиторий как подмодуль `olcos-core/` и
добавляют к нему только интерфейс и системную часть VPN.

## Что внутри

| Папка | Что там |
|---|---|
| `olcrtc/` | ядро [olcrtc](https://github.com/ghostlane-project/olcrtc) (Apache-2.0) на релизе из `olcrtc.upstream` и изменения olcOS поверх него отдельными коммитами |
| `mobile/` | модуль для gomobile: tun2socks (`tunstack`), склейка комнат в режиме «Весь сервер» (`bond`) и агент сервера (`agent`) |
| `engine/`, `profile/`, `olcos/` | общий интерфейс движков, разбор ссылок `olcrtc://` и `vless://`, движок Xray |
| `server/` | установка olcrtc на сервер (`srv.sh`), установщик одной командой (`install.sh`), Xray, скрипты агента и патч ядра для сервера |
| `scripts/` | сборка для iOS и Android, генерация патча, обновление olcrtc, проверки |
| `docs/` | [устройство](docs/architecture.md) и [как устроен olcrtc здесь](docs/olcrtc.md) |

Оба приложения собирают ядро одним вызовом gomobile: два Go-фреймворка нельзя положить в одно приложение, у каждого
свой рантайм. Сервер собирает то же ядро из olcrtc нужного коммита и патча `server/olcrtc-core.patch`, а приложения
сверяют версию ядра на сервере со своей и предлагают обновить его, если они расходятся.

## Сервер одной командой

На чистом VPS с Debian, Ubuntu, Fedora или CentOS под root:

```bash
curl -fsSL https://raw.githubusercontent.com/olcOS/olcos/main/install.sh | sudo bash
```

Команда из главного репозитория скачивает `server/install.sh` отсюда, ставит olcrtc и агента и печатает
приглашение. Его нужно отсканировать в olcOS, и телефон станет владельцем сервера. Настройки описаны в начале
[server/install.sh](server/install.sh).

## Сборка

Нужен Go версии из `mobile/go.mod`.

```bash
git clone https://github.com/olcOS/olcos-core
cd olcos-core
scripts/build-ios.sh          # macOS и Xcode, результат: build/Mobile.xcframework
scripts/build-android.sh      # JDK, Android SDK и NDK, результат: build/olcoscore.aar
```

Проверки, которые запускает CI:

```bash
go test ./...                              # движки и профили
(cd mobile && go test ./...)               # tunstack, склейка, агент
python3 scripts/parity_check.py            # srv.sh не отстал от olcrtc/install.sh
scripts/make-core-patch.sh --check         # патч сервера совпадает с olcrtc/
python3 scripts/test_server_scripts.py
python3 scripts/test_xray_server_script.py
```

## Изменения в olcrtc и обновление

Правки в `olcrtc/` делаются обычными коммитами, после них нужно перегенерировать патч сервера. Новый релиз olcrtc
подтягивается одной командой `scripts/update-olcrtc.sh <тег>`. Подробности и ограничения в
[docs/olcrtc.md](docs/olcrtc.md).

## Ошибки и безопасность

Ошибки приложений описывайте в [Issues главного репозитория](https://github.com/olcOS/olcos/issues), ошибки ядра и
скриптов сервера можно и здесь. Не публикуйте ссылки подключения, ключи и адреса своих серверов. Об уязвимостях
сообщайте приватно, см. [SECURITY.md](SECURITY.md).

## Лицензия

Код olcOS распространяется по [лицензии MIT](LICENSE). Каталог `olcrtc/` распространяется по Apache-2.0, см.
[olcrtc/LICENSE](olcrtc/LICENSE) и [olcrtc/NOTICE](olcrtc/NOTICE). Сторонние компоненты перечислены в [NOTICE](NOTICE).
