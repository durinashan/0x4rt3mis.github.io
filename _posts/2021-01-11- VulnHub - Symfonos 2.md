---
title: "VulnHub - Symfonos 2"
tags: [Linux,Easy,SMTP Poisoning,Log Poison,Wordpress,Gobuster,LFI,Smbclient,Path]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-1,322/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 5 portas abertas no servidor

> Porta 21 - Servidor FTP

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

> Portas 139 e 445 -> Servidor SMB

## Enumeração da Porta 80 (Web)

Abrimos ela no navegador pra se tem algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/web.png)

Vamos rodar o gobuster também

```bash
gobuster dir -u http://192.168.56.106/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/web1.png)

Nada... vamos prosseguir...

## Enumeração da Porta 445

Bom, sabendo que é um servidor samba, vamos ver se tem algum share disponível

```bash
smbclient -L \\192.168.56.106
```

Apareceu um **anonymous** ali, interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb.png)

Entamos nele

```bash
smbclient //192.168.56.106/anonymous
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb1.png)

Passamos esse arquivo **log.txt** para nossa máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb2.png)

Verificamos que é um arquivo de configuração

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos2/smb3.png)