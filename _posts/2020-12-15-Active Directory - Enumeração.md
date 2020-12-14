---
title: "Active Directory - Enumeração"
tags: [Windows, Active Directory]
categories: Active Directory
---

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/enum.png)

# Considerações Iniciais

Agora vamos iniciar a enumeração de um Active Directory, que é o primeiro passo a ser realizado em qualquer atividade ofensiva.

A ferramenta que utilizarei para essa seção é o PowerView.ps1, um script escrito em PowerShell que possibilita a enumeraçã rápida e precisa de tudo (quase) que existe dentro do ambiente AD!

Link para download do Script

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

E claro, obviamente, esconderei todas as menções para qual ambiente estou realizando a enumeração, aqui é apenas para fins didáticos!

# Domain Enumeration

Vamos iniciar e enumeração!

Logicamente após termos baixado o script devemos realizar a importação dele, com o comando `Import-Module PowerView.ps1`

## User Enumeration

O comando para realização da enumeração de usuários dentro de ambiente AD é

`Get-NetUser | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/user.png)

E aqui são listados todos os usuários que estão cadastrados dentro do Active Directory.

## Group Enumeration

O comando para realização da enumeração de grupos dentro de ambiente AD é

`Get-NetGroup | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/group.png)

E aqui estão todos os grupos dentro do AD.

## Enumeração de Computadores

Sim, isso mesmo, podemos vizualizar todos os computadores que estão cadastrados dentro do domínio!

O comando para isso é:

`Get-NetComputer | select Name`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/computer.png)

A partir dai já começamos a ver quais são nossos possíveis alvos!

## Enumeração de Domain Admins

O comando para enumerarmos todos os Domains Admins é:

`Get-NetGroupMember "Domain Admins"`

![](https://raw.githubusercontent.com/0x4rt3mis/0x4rt3mis.github.io/master/img/active-enum/da.png)