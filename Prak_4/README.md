# Развертывание Threat intelligence Platform OpenCTI

## Цель работы

1. Освоить базовые подходы процессов Threat Intelligence;
2. Освоить современные инструменты развертывания контейнеризованных приложений;
3. Получить навыки поиска информации об угрозах ИБ.

## Ход выполнения работы

Разворачивание системы Threat Intelligence OpenCTI осуществлялось с помощью Docker.

1. Для работы с ElasticSearch требуется увеличить размер виртуальной памяти системы:
```
sudo sysctl -w vm.max_map_count=1048575
```
2. В новой директории был создан файл .env для хранения параметров окружения.
-   Содержание файла .env:
```
OPENCTI_ADMIN_EMAIL=admin\@opencti.io

OPENCTI_ADMIN_PASSWORD=admininistrator

OPENCTI_ADMIN_TOKEN=cedd95c3-744d-43ef-a300-2bc54a99baad

OPENCTI_BASE_URL=http://localhost:8080

MINIO_ROOT_USER=opencti

MINIO_ROOT_PASSWORD=administrator

RABBITMQ_DEFAULT_USER=opencti

RABBITMQ_DEFAULT_PASS=admininistrator

CONNECTOR_EXPORT_FILE_STIX_ID=dd817c8b-abae-460a-9ebc-97b1551e70e6

CONNECTOR_EXPORT_FILE_CSV_ID=7ba187fb-fde8-4063-92b5-c3da34060dd7

CONNECTOR_EXPORT_FILE_TXT_ID=ca715d9c-bd64-4351-91db-33a8d728a58b

CONNECTOR_IMPORT_FILE_STIX_ID=72327164-0b35-482b-b5d6-a5a3f76b845f

CONNECTOR_IMPORT_DOCUMENT_ID=c3970f8a-ce4b-4497-a381-20b7256f56f0

SMTP_HOSTNAME=localhost

ELASTIC_MEMORY_SIZE=4G
```         

3. В этой же директории создан файл docker-compose.yml
-   Запуск контейнера с помощью команды:
```
sudo docker-compose up -d

lab4_redis_1 is up-to-date

lab4_rabbitmq_1 is up-to-date

Starting lab4_minio_1 ...

lab4_elasticsearch_1 is up-to-date

Starting lab4_minio_1 ... done

Creating lab4_opencti_1 ...

Creating lab4_opencti_1 ... done

Creating lab4_connector-import-document_1 ...

Creating lab4_connector-import-file-stix_1 ...

Creating lab4_connector-export-file-stix_1 ...

Creating lab4_connector-export-file-csv_1 ...

Creating lab4_worker_1 ...

Creating lab4_worker_2 ...

Creating lab4_worker_3 ...

Creating lab4_connector-export-file-txt_1 ...

Creating lab4_connector-export-file-txt_1 ... done

Creating lab4_connector-import-file-stix_1 ... done

Creating lab4_connector-export-file-stix_1 ... done

Creating lab4_connector-import-document_1 ... done

Creating lab4_connector-export-file-csv_1 ... done

Creating lab4_worker_3 ... done

Creating lab4_worker_2 ... done

Creating lab4_worker_1 ... done
``` 

4.  Заходим в веб-интерфейс OpenCTI \\\`localhost:8088\\\`

Входим по данным пользователя:

![image](https://github.com/artem12786/SAZA/assets/77270613/1c4b221c-3086-4ffc-8bec-7376309396be)

5\. Попадаем на главную страницу

![image](https://github.com/artem12786/SAZA/assets/77270613/2a3aa082-f753-44c0-82c0-c476a2cc1862)

6\. Далее используем данный код для импорта данных из файла hosts.txt

```{python}
import stix2

indicators = []
with open('hosts.txt') as f:
    for domain in f:
        domain = domain.strip()  # Удаление лишних пробельных символов по краям строки

        if not domain:  # Пропуск пустых строк
            continue

        try:
            indicator = stix2.Indicator(
                name=f'Malicious Domain: {domain}',
                pattern="[domain-name:value = '{}']".format(domain),
                pattern_type="stix",
                labels=['malicious host']
            )
            indicators.append(indicator)
        except stix2.exceptions.InvalidValueError:
            print(domain)
            continue

bundle = stix2.Bundle(objects=indicators)

# Запись пакета в файл STIX
with open('malicious_domains.stix', 'w') as f:
    f.write(bundle.serialize(indent=4))

```

Импортируем данные:

![image](https://github.com/artem12786/SAZA/assets/77270613/e08a659b-0ef0-4c92-b49b-9c57df13c1e0)

![image](https://github.com/artem12786/SAZA/assets/77270613/084f1c9b-0c29-4a6c-8546-296ad89ecab7)

В результате не было найдено вредоносных доменов:

![image](https://github.com/artem12786/SAZA/assets/77270613/b7a852d9-7d7b-4c56-8369-8c20bbc82038)

## Оценка результата

С помощью платформы OpenCTI удалось проанализировать трафик на предмет перехода по нежелательным доменам.

## Выводы

Таким образом, были изучены возможности работы с платформой threat intelligence OpenCTI
