# Развертывание системы мониторинга ELK Stack

## Цель работы

1. Освоить базовые подходы централизованного сбора и накопления информации
2. Освоить современные инструменты развертывания контейнирозованных приложений
3. Закрепить знания о современных сетевых протоколах прикладного уровня

## Ход выполнения практической работы

### Задание 1. Развернуть систему мониторинга на базе ElasticSearch

1. Настройка

Для работы ElasticSearch требуется увеличить размер виртуальной памяти системы:

```()
sudo sysctl -w vm.max_map_count=262144
```

Далее следуем инструкции по ссылке:

https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html

2. После формирования файлов с конфигурациями, нужно запустить образы командой

```()
docker-compose up -d
```

![All text](https://github.com/MoonFlower18/threat_hunting/blob/main/Prak_3/%D0%A1%D0%BA%D1%80%D0%B8%D0%BD%D1%88%D0%BE%D1%82%D1%8B/1.png)

3. Переходим на `localhost:5061` и авторизируемся

![All text](https://github.com/MoonFlower18/threat_hunting/blob/main/Prak_3/%D0%A1%D0%BA%D1%80%D0%B8%D0%BD%D1%88%D0%BE%D1%82%D1%8B/2.png)

4. Проверям, что установленны все средства для сбора информации из файлов журналов и сбора аналитики трафика

![All text](https://github.com/MoonFlower18/threat_hunting/blob/main/Prak_3/%D0%A1%D0%BA%D1%80%D0%B8%D0%BD%D1%88%D0%BE%D1%82%D1%8B/3.png)

5. Создаем новый DataView для filebeat

![Att text](https://github.com/MoonFlower18/threat_hunting/blob/main/Prak_3/%D0%A1%D0%BA%D1%80%D0%B8%D0%BD%D1%88%D0%BE%D1%82%D1%8B/4.png)

6. Создаем новый DataView для packetbeat

![All text](https://github.com/MoonFlower18/threat_hunting/blob/main/Prak_3/%D0%A1%D0%BA%D1%80%D0%B8%D0%BD%D1%88%D0%BE%D1%82%D1%8B/5.png)

## Оценка результата

Была развёрнута система ElasticSearch и настроена система сбора трафика и лог-файлов.

## Вывод

В результате работы была освоена система контейнеризации приложений Docker, работа с Docker-compose и освоена система централизованного сбора и накопления информации ElasticSearch.
