<div style="display: flex; justify-content: center;">
  <img src="./Imagens/ISHLOGO.png" alt="Logo 1" width="300" height="300">
  <img src="./Imagens/Logo_Heimdall_Horizontal_Cor_Anexo_ISH.png" alt="Logo 2" width="300" height="300">
</div>

# Análise Técnica da Kill Chain - Akira: Evasão de Defesa

$\color{black}{\textsf{Pesquisador}}$ : $\color{purple}{\textsf{Bryenne Bonfim}}$

$\color{black}{\textsf{Tipo de Ameaça}}$ : $\color{orange}{\textsf{TTP}}$

$\color{black}{\textsf{TLP}}$ :  $\color{red}{\textsf{RED}}$

$\color{black}{\textsf{Nível de Impacto}}$ :  $\color{red}{\textsf{Critico}}$

$\color{black}{\textsf{Tipo de Impacto}}$ :  $\color{red}{\textsf{Acesso Incial / Persistência}}$

--------------------------------------

Descoberto pela primeira vez no início de 2023, o ransomware Akira parecia ser apenas mais uma família de ransomware que entrou no mercado. Sua atividade contínua e inúmeras vítimas são nossos principais motivadores para investigar o funcionamento interno do malware para capacitar as equipes azuis a criar regras defensivas adicionais fora de sua segurança já implementada.

## Cadeia de infecção e técnicas

O ransomware Akira normalmente obtém acesso aos ambientes das vítimas usando credenciais válidas que foram possivelmente obtidas de seus afiliados ou outros ataques. Ele foi observado usando ferramentas de terceiros, como PCHunter, AdFind, PowerTool, Terminator, Advanced IP Scanner, Windows Remote Desktop Protocol (RDP), AnyDesk, Radmin, WinRAR e a ferramenta de tunelamento da Cloudflare. A Figura abaixo mostra a cadeia de infecção do Akira:

<p align="center">
  <img src="Imagens/rs-akira-figure-8rFZBkyZ.jpg">
  <br>
  Figura 1: A cadeia típica de infecção do ransomware Akira
</p>

Os dados recuperados do sistema do ator totalizaram 99 GB e incluíram diversas ferramentas autônomas para exploração e reconhecimento de VPN, juntamente com um diretório de ferramentas apropriadamente nomeado , contendo uma coleção de utilitários de pentesting de código aberto.

A partir da avaliação de comandos executados no sistema, este sistema é avaliado como tendo sido usado principalmente para conduzir exploração inicial e exfiltração de dados. Enquanto os operadores do sistema instalaram ferramentas de reconhecimento (como reconftw ) e pós-exploração, seu uso delas parece limitado a testes. 

## Evasão de Defesa

O Akira emprega técnicas de evasão de defesa utilizando as ferramentas **KillAV** e **PowerTool** para desativar processos relacionados a softwares de segurança. Essas ferramentas exploram o driver do **Zemana AntiMalware** para encerrar processos de antivírus, permitindo que o ransomware opere sem detecção. 

Especificamente, o PowerTool é utilizado para explorar o driver do Zemana AntiMalware, permitindo que o Akira termine processos de antivírus e outros softwares de segurança. Essa técnica facilita a movimentação lateral dentro da rede da vítima e a execução de atividades maliciosas sem interrupções.

Além disso, o Akira utiliza o KillAV, uma ferramenta que também explora o driver do Zemana AntiMalware para desativar processos de antivírus. Essa abordagem permite que o ransomware evite a detecção por soluções de segurança e continue suas operações maliciosas. 

Essas técnicas de evasão de defesa são parte das táticas empregadas pelo Akira para comprometer sistemas e redes, desativando medidas de segurança e facilitando a execução de suas atividades maliciosas.

 
## Emulação de Ameaça: KillAV



## Detecção de Ameaça:

## Engenharia de Detecção

Na seção a seguir, vamos sintetizar como caçar os indicadores de comprometimento produzidos pelo acesso remoto na  vítima, a criação de contas novas na vítima e no controlaodr de domínio e a adição do usuário ao grupo de segurança **Domain Admins** em busca de persistência.

### Caçando Indicadores de Comprometimento

----------------

### Padrão SIGMA: Akira: 

```yaml
title: 'Windows - Akira: 
id: 
status: stable
description: 
references: 
    - 
author: CTI Purple Team - Bryenne Soares
date: 20/12/2024
tags:
    -
logsource:
    category: security
    product: windows
    definition: sysmon
detection:
    selection_logon|contains:
      EventID:
      - 4624  # Successful logon
      - 4625  # Failed logon
    selection_user_creation:
      EventID:
      - 4720  # User account creation
      - 4722  # User account enabled
      - 4732  # User added to security-enabled global group
    selection_registry_modification|contains:
      EventID:
      - 4657 # Um valor do registro foi modificado.
      winlog.event_data.ObjectName:
      - '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist'
    selection_process_creation|contains:
      EventID:
      - 4688 # Um processo foi criado.
      process.name:
      - 'reg.exe'
    condition:       
fields:
    - 
falsepositives:
    - "É necessário validar se foi realizado uma ação administrativa de conhecimento da equipe de infraestrutura"
level: high
```