# Prizrak-Core с zapret2 для Windows x64

1. Распакуйте ZIP. В PowerShell из этой папки выполните `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup-zapret2.ps1`. Скрипт скачает [официальный zapret2 v1.0.7](https://github.com/bol-van/zapret2/releases/tag/v1.0.7), проверит SHA-256 и распакует его рядом. Для установки из уже скачанного ZIP укажите `-ArchivePath` с путём к нему.
2. Остановите прежний zapret и другие процессы перехвата трафика. В командной строке, запущенной от имени администратора, выполните `start-zapret2.cmd` из распакованной папки. `winws2` работает отдельно от Prizrak-Core, а `Ctrl+C` в его окне останавливает обработку.
3. Проверьте загрузку и перемотку видео на YouTube. Для проверки QUIC откройте YouTube напрямую в браузере с включённым HTTP/3 и проверьте `h3` в колонке Protocol в DevTools → Network. Для сравнения повторите тест после остановки `winws2`, используя новые соединения.
4. Для проверки через Prizrak-Core запустите `prizrak-core.exe -f config.yaml` в отдельном обычном терминале и укажите в браузере локальный HTTP-прокси `127.0.0.1:17890`. Этот путь проверяет TLS по TCP. Тестовый YAML использует `DIRECT`, поэтому трафик до YouTube виден `winws2`.

Профиль `youtube-winws2.txt` использует YouTube-правила из [примера автора](https://github.com/bol-van/zapret-win-bundle/blob/6b4375fa04f6bd7017eec379e16e462d3ea8df66/zapret-winws/preset2_example.cmd) для TLS и QUIC. Действия применяются к хостам из `youtube-hosts.txt`. WinDivert перехватывает подходящий исходящий трафик всей системы, включая браузер и прямые соединения Prizrak-Core. Результат зависит от сети и провайдера.

Для базового теста скачайте вариант `compatible`. Вариант `v3` рассчитан на процессоры с поддержкой x86-64-v3. Оба варианта используют одинаковый zapret2.
