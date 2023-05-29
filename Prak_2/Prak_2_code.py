with open("dns.log") as f:
    lines_dns = f.readlines()
    dns_hosts = [line.split()[9] for line in lines_dns if len(line.split()) > 9]
f.close()
with open("evil_hosts.data") as f:
    lines_evil = f.readlines()
    evil_hosts = [line.split()[1] for line in lines_evil if len(line.split()) > 1]
f.close()
c=0
for i in range(len(dns_hosts)):
    for j in range(len(evil_hosts)):
        if dns_hosts[i] == evil_hosts[j]:
            c += 1
evil_dns = c/(len(evil_hosts))
print("Кол-во совпадений DNS имен из загруженных списков трафика:", c)
print("Процент нежелательного трафика:", evil_dns)