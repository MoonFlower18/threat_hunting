# Получение сведений о системе

## Цель работы

Получить сведения об используемой системе

## Исходные данные

1. Ноутбук Asus
2. Windows 10

## План

1. Получить сведения о версии ядра
2. Получить сведения о процессоре
3. Получить последние 30 строк логов системы

## Ход работы

1. Получим сведения о версии ядра:

```{PowerShell}
winver
```

В результате выполнения данной команды была получена версия ядра - 21H2(сборка ОС 19044.1826)

2. Далее получим сведения о процессоре:

```{PowerShell}
Get-WmiObject win32_Processor
```

```{PowerShell}
Caption           : Intel64 Family 6 Model 140 Stepping 1
DeviceID          : CPU0
Manufacturer      : GenuineIntel
MaxClockSpeed     : 3110
Name              : 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz
SocketDesignation : U3E1
```

3. Далее получим последние 30 строк логов системы:

```{PowerShell}
Get-EventLog -LogName 'system' -Newest 30
```

```{PowerShell}
Index Time          EntryType   Source                 InstanceID Message
   ----- ----          ---------   ------                 ---------- -------
   71364 март 21 04:47  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71363 март 21 04:41  Information Microsoft-Windows...          507 Не найдено описание для события с кодом '507' в...
   71362 март 21 04:37  Information Microsoft-Windows...          506 Не найдено описание для события с кодом '506' в...
   71361 март 21 04:37  Information Microsoft-Windows...          507 Не найдено описание для события с кодом '507' в...
   71360 март 21 04:37  Information Microsoft-Windows...          105 Не найдено описание для события с кодом '105' в...
   71359 март 21 04:08  Information Microsoft-Windows...          506 Не найдено описание для события с кодом '506' в...
   71358 март 21 04:07  Information Microsoft-Windows...          507 Не найдено описание для события с кодом '507' в...
   71357 март 21 01:53  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71356 март 21 01:53  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71355 март 21 01:24  Information Microsoft-Windows...           19 Установка завершена: следующее обновление было ...
   71354 март 21 01:24  Information Microsoft-Windows...           43 Установка начата: ОС Windows начала устанавлива...
   71353 март 21 01:24  Information Microsoft-Windows...           44 Центр обновления Windows начал скачивать обновл...
   71352 март 21 01:23  Information Microsoft-Windows...          158 Поставщик времени "VMICTimeProvider" указал, чт...
   71351 март 21 01:06  Information Microsoft-Windows...          158 Поставщик времени "VMICTimeProvider" указал, чт...
   71350 март 21 00:49  Information Microsoft-Windows...          158 Поставщик времени "VMICTimeProvider" указал, чт...
   71349 март 21 00:32  Information Microsoft-Windows...          158 Поставщик времени "VMICTimeProvider" указал, чт...
   71348 март 21 00:29  Information Microsoft-Windows...          506 Не найдено описание для события с кодом '506' в...
   71347 март 21 00:21  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71346 март 21 00:18  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71345 март 21 00:17  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71344 март 21 00:16  Warning     DCOM                        10016 Не найдено описание для события с кодом '10016'...
   71343 март 21 00:15  Information Microsoft-Windows...          507 Не найдено описание для события с кодом '507' в...
   71342 март 21 00:15  Warning     Microsoft-Windows...         1014 Разрешение имен для имени wpad истекло после от...
   71341 март 21 00:15  Information Microsoft-Windows...          506 Не найдено описание для события с кодом '506' в...
   71340 март 21 00:15  Information Microsoft-Windows...           37 NTP-клиент поставщика времени получает действит...
   71339 март 21 00:15  Warning     Microsoft-Windows...          134 NTP-клиенту не удалось задать настроенный вручн...
   71338 март 21 00:15  Information Microsoft-Windows...          158 Поставщик времени "VMICTimeProvider" указал, чт...
   71337 март 21 00:15  Information Microsoft-Windows...          507 Не найдено описание для события с кодом '507' в...
   71336 март 21 00:15  Information Microsoft-Windows...          172 Не найдено описание для события с кодом '172' в...
   71335 март 21 00:15  Information Microsoft-Windows...          105 Не найдено описание для события с кодом '105' в...

```

## Оценка результата

В результате лабораторной работы была получена базовая информация об используемой системе.

## Вывод

Таким образом. мы научились, используя команды Windows, получать сведения о системе.