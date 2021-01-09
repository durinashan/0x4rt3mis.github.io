---
title: "VulnHub - Prime 1"
tags: [Linux,Easy]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/inicial.png)

Link: <https://www.vulnhub.com/entry/prime-1,358/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta (Não vou rodar essa flag pq teve uma saída bem bizarra)

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Primeira coisa a se fazer sempre é verificar o que está sendo executado na porta 80, então vamos abrir o navegador para ver

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/web.png)

Pelo estilo de site, tem muito cara de ser Drupal, pelas cores e tudo mais, mas não é! É um php simples mesmo.

### Gobuster

Como de costume quando temos um website vamos jogar para o Gobuster pra vermos o que pode ser feito nesse site

```bash
gobuster dir -u http://192.168.56.104/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/gobuster.png)

Encontramos alguns diretórios com o gobuster, vamos acessar o `/dev`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/dev.png)

Nada de interessante... Aqui fala pra tentarmos mais ou outras ferramentas

Então agora rodamos o gobuster também pra procurar por arquivos `.txt`

```bash
gobuster dir -u http://192.168.56.104/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/gobuster1.png)

Esse secret.txt nos chamou atenção, então vamos verificar do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/secret.png)

Nos fala sobre tentar fazer um fuzzing com o wfuzz

**https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/web1.png)

Então vamos utilizar ela pra descobrir parâmetros dentro do site

### Wfuzz

```bash
wfuzz -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hw 19 http://192.168.56.104/index.php?file=FUZZ.txt
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wfuzz.png)

Explicação parâmetros do wfuzz

```
-t 200 -> Aumento de threads, para ir mais rápido
-c -> Cores
-w -> Wordlist
--hw -> Vai esconder todas as respostas que tem 19 palavras, ou seja, as saidas de erro
```

Encontramos o `location.txt`, interessante, vamos ver o que tem nele

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/location.png)

Aqui ele fala pra usarmos o parâmetro `secrettier360` para encontrar algum php bacana, vamos lá então

```bash
wfuzz -t 200 -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hw 12 http://192.168.56.104/index.php?secrettier360=FUZZ.php
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-prime1/wfuzz1.png)

Não encontramos nada de útil...