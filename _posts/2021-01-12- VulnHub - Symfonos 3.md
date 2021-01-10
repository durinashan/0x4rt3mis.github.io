---
title: "VulnHub - Symfonos 3"
tags: [Linux,Medium]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-31,332/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 3 portas abertas no servidor

> Porta 21 -> Servidor FTP

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 21 (FTP)

Primeira coisa é tentarmos login anonimo

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/ftp.png)

Não deu certo... então vamos procurar exploits para essa versão do ftp

```bash
searchsploit ProFTPD 1.3.5
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/ftp1.png)

## Enumeração da Porta 80 (Web)

Abrimos ela no navegador pra se tem algo de interessante

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web.png)

Vamos rodar o gobuster também

```bash
gobuster dir -u http://192.168.56.107/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web1.png)

Encontramos esse **/gate** vamos ver ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web2.png)

Certo, outro gobuster nele

```bash
gobuster dir -u http://192.168.56.107/gate -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web3.png)

Encontramos esse **/cerberus** vamos ver ele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web4.png)

Certo, outro gobuster nele

```bash
gobuster dir -u http://192.168.56.107/gate/cerberus -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
```

Troquei a lista pra medium, e mesmo assim não achou nada

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/web5.png)

### Encontrando o CGI-BIN/

Aqui foi interessante, tem que prestar bastante atenção, pq senão não encontramos essa pasta cgi-bin, que vai nos dar acesso à máquina...

Mas por que não? A wordlist que eu utiliza (que é boa por sinal) não tem a palavra cgi-bin/, sim, com a / no final...

Pô, mas isso faz diferença?

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista.png)

Sim, faz, pq olha as diferentes respostas que o site da pra com a / ou sem a /

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista1.png)

Um da 404 e outro 403... interessante não? Então agora vamos rodar o gobuster novamente com uma wordlist que possua o cgi-bin/

```bash
gobuster dir -u http://192.168.56.107/cgi-bin/ -w /usr/share/wordlists/dirb/big.txt -t 100
```

Achamos!

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista2.png)

Agora rodamos novamente o gobuster dentro do cgi-bin pra ver se tem algo que possamos fazer

```bash
gobuster dir -u http://192.168.56.107/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos3/lista3.png)

