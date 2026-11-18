# Prizrak-Core со встроенным zapret2

1. Распакуйте ZIP для Windows x64. Начните с варианта `compatible`. Оставьте `WinDivert.dll` и `WinDivert64.sys` рядом с `prizrak-core.exe`.
2. Остановите старый zapret или `winws2`, если они запущены. Откройте командную строку от имени администратора в распакованной папке и выполните `prizrak-core.exe -d . -f config.yaml`.
3. Укажите в браузере HTTP-прокси `127.0.0.1:17890`. Откройте и перемотайте видео на YouTube. Этот маршрут проверяет TLS по TCP. Для QUIC направьте UDP-трафик приложения в `ZAPRET2` через TUN или SOCKS5 UDP.

В `config.yaml` стратегии и профили задаются в `proxies[].zapret2.options` в порядке выполнения. `tcp-ports` и `udp-ports` задают порты подключения, которые обрабатывает этот outbound. `-t -d . -f config.yaml` проверяет стратегию, загрузку Lua и доступность драйвера.

В ядро встроены C-движок и Lua-библиотеки [zapret2 v1.0.7](https://github.com/bol-van/zapret2/releases/tag/v1.0.7). Пакеты обрабатываются в WebAssembly внутри `prizrak-core.exe`. Тестовый профиль использует TLS- и QUIC-правила из [примера автора](https://github.com/bol-van/zapret-win-bundle/blob/6b4375fa04f6bd7017eec379e16e462d3ea8df66/zapret-winws/preset2_example.cmd).

Этот эксперимент перехватывает собственные TCP/UDP-соединения outbound. TCP-перехват включается после установления соединения, поэтому стратегии для SYN/SYN-ACK здесь недоступны. Модуль видит встроенные Lua-файлы и блобы. Имена хостов задаются через `--hostlist-domains`, пользовательский Lua можно передать строкой `--lua-init=...`. Отправка ограничена текущим соединением. Системные флаги `winws2`, IP-фрагментация и отправка в другие соединения не поддерживаются.

Исходники зависимостей и лицензии доступны у [zapret2](https://github.com/bol-van/zapret2/tree/v1.0.7), [WinDivert](https://github.com/basil00/WinDivert/tree/v2.2.2), [Lua](https://www.lua.org/ftp/lua-5.4.8.tar.gz), [zlib](https://zlib.net/fossils/zlib-1.3.1.tar.gz) и [wasi-libc](https://github.com/WebAssembly/wasi-libc). Патч и сборка WASM находятся в `transport/zapret2/build` в исходниках Prizrak-Core.
