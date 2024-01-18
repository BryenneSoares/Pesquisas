
<p align="center">
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Movimentação Lateral Através do Invoke-SMBExec

Na pesquisa desta semana, iremos explorar as características de uma ferramenta amplamente utilizada por adversários, e já identificada pela equipe de *DFIR* da ISH Tecnologia em respostas a incidentes, o ***Invoke-SMBExec***.

A ideia por trás do SMBExec não é nova, pois o seu vetor de ataque é amplamente conhecido e utilizado por diversos adversários, com o propósito de alcançar a movimentação lateral através da infraestrutura das vítimas. Estamos falando da exploração do protocolo SMB, que se não tiver bem configurada, dará capacidade aos adversários de se mover através da infraestrutura.

O *Purple Team* já fez uma pesquisa referente a movimentação lateral por meio do SMB, através da pesquisa referente ao uso do *PSExec*.

Porém, o que veremos nesta nova pesquisa, é a capacidade do adversário de alcançar o mesmo resultado através do PowerShell, e sem tocar no disco.

## Contexto

Para que o adversário possa executar estas ações, ele já deve ter alcançado o ***acesso inicial*** e provavelmente alcançado a ***evasão de defesas*** e ***coletas de credenciais***. Por isso o seu próximo movimento será a busca de novos dispositivos na infraestrutura, que possam ser acessados por meio das credenciais coletadas.


## Análise e Execução do SMBExec

O [SMBExec](https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBEnum.ps1) é uma ferramenta open-source desenvolvida pelo ***Kevin Robertson***, e tal ferramenta faz parte da biblioteca [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash/tree/master) (também desenvolvida pelo mesmo ator).

Nesta seção vamos explorar os pontos mais importantes do código fonte do *SMBExec*, e algumas características constantes que nos ajudarão a identificar quando esta ferramenta, ou ferramentas similares, forem executadas em um dispositivo. Abaixo, podemos observar o cabeçalho da *ferramenta*.

<p align="center">
  <img src="imagens/2.smbexec_header.png">
</p>

Como podemos observar na imagem acima, o SMBExec permite a execução de comandos remoto, por meio da execução da técnica de ***Pass-The-Hash*** utilizando as credenciais em formato *NTLMv2*. A ferramenta também possui suporte para atuar por meio dos protocolos ***SMBv1*** e ***SMBv2***.

Portanto, estas informações nos permitem compreender que ao coletar as *Hashes NTLM*, o adversário pode utilizar o **SMBExec** para executar um *Pass-The-Hash* por meio do protocolo *SMB*.

Ao analisar o código fonte, podemos ver a sequência de características que serão constantes em futuras versões desta ferramenta.

<p align="center">
  <img src="imagens/4.new-packet-smb-negotiate-protocol-request.png">
</p>

Acima, podemos observar uma sequência de bytes que também é vista nas versões do ***EternelBlue*** desenvolvidas em *PowerShell*, um exploit que explora a vulnerabilidade **MS17-010** (amplamente utilizada pelo ***WannaCry***). Na imagem abaixo, podemos observar esta mesma sequência de bytes presentes numa versão em *PowerShell* do *EternalBlue*, praticamente no mesmo contexto de construção de pacote *SMB* para requisição.

<p align="center">
  <img src="imagens/5.ms17-010-scanner-protocol-negotiate.png">
</p>

Ao continuar nossa análise, nós somos capazes de observar outra constante, que se trata do compartilhamento administrativo oculto alvo desta ferramenta (e também de ferramentas como o ***EternalBlue*** e ***PsExec***), o **IPC$**.

<p align="center">
  <img src="imagens/6.ipc$_targeted_pipe_name.png">
</p>

Na imagem abaixo, na função referente a configuração da conexão *SMB*, também é possível observar que a ferramenta tem como alvo um pipe específico (*svcctl*), que iremos identificar de maneira mais clara, a utilização este recurso que será acessado pela ferramenta por meio do compartilhamento administrativo oculto *IPC$*.

Outras duas constante interessantes a serem levadas em conta, são as assinaturas do protocolo a ser utilizado, durante a função de configuração da conexão *SMB*. Abaixo, podemos observar o ID do protocolo **SMBv1**.

<p align="center">
  <img src="imagens/8.smb1_header.png">
</p>

E na imagem abaixo, também podemos observar o ID do protocolo **SMBv2**.

<p align="center">
  <img src="imagens/9.smb2_header.png">
</p>

Como sabemos, ferramentas podem ser alteradas e o SMBExec analisado é a sua versão original e em texto puro. Um adversário habilidoso pode realizar modificações com o propósito de evadir defesas. O método mais utilizado, é a alteração de nomes de funções e variáveis, alteração do nome do script a ser executado, e a exclusão de comentários do código original. Mas, como podemos observar na imagem acima, nos concentramos nas informações constantes e que são essenciais para o funcionamento desta ferramenta.

Agora, vamos observar como podemos utilizar de maneira básico o *SMBExec*. Abaixo, podemos observar que a ferramenta tem uma fácil utilização.

<p align="center">
  <img src="imagens/17.emulation.png">
</p>

Acima, podemos observar que o fluxo de execução é bem parecido com a execução do *PsExec*. Uma conexão é feita por meio do protocolo ***SMB*** através do compartilhamento oculto administrativo *IPC$*, o usuário é autenticado no dispositivo alvo, um serviço é criado e executado no dispositivo alvo, e por meio da execução deste serviço o usuário alcança o propósito de execução de comando remoto.

Na seção a seguir, vamos analisar como podemos executar detectar a execução desta ferramenta desenvolvida em *PowerShell*, e validar a reutilização de uma detecção já criada por meio da pesquisa do Purple Team, referente ao **PsExec**.

## Análise de Comportamento

Como identificamos na seção anterior, o código-fonte da ferramenta ***SMBExec*** possui algumas constantes, que também podem ser identificadas em outras ferramentas com propósitos similares.

São elas:

- **ID dos Protocolos SMBv1 e SMBv2**: ;
- **Referência do svcctl em bytes**: ;
- **Referências ao compartilhamento oculto IPC$**;
- **Configurações de Pacotes SMB**: ;

Para identificar estas características no dispositivo que executou a ferramenta, precisaremos ter o log do ***PowerShell Script Block Logging*** ativo, o ***Event ID 4104***. Este log, é responsável por registrar todas as execuções de comando por meio de **CMDlets**, no prompt do *PowerShell*.

Abaixo podemos observar um bom exemplo de identificação das constantes acima. Na imagem a seguir, é possível identificar a sequência de bytes referente a ao ID do protocolo a ser utilizado.

<p align="center">
  <img src="imagens/11.smb_packet_creation_detection.png">
</p>

Este, e as demais constantes observadas no código podem ser identificadas por meio do ***Event ID 4104***.

### Reutiização da Regra de Detecção do PsExec e de Criação de Serviços Maliciosos.

Como foi possível observar, se você leu ou assistiu ao [Webinar](https://ishtecnologia.sharepoint.com/:v:/s/CTI-PurpleTeam/EXxP0PKWVJlAuad4KmBTUoAB9P-aQ0ebrhlVtrFO5_ejWg?e=Pu4GpV) da pesquisa de Movimentação Lateral Através do PSExec, você já perecebeu que o fluxo de execução do *SMBExec* é semelhante ao fluxo de execução do PsExec.

Parte deste fluxo é o *logon com o tipo 3* ([**Event ID 4624**](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)) e o acesso a escrita do compartilhamento oculto administrativo **IPC$**. Isso pode ser visto na imagem abaixo.

<p align="center">
  <img src="imagens/14.ipc_write_data.png">
</p>

Ou seja, de fato, é semelhante o suficiente para que a nossa regra de detecção [BASELINE - Lateral Movement - Possible Lateral Movement Through PSExec](https://github.com/ish-cti-purple/CTI-PurpleTeam/blob/main/Regras/Sigma/Lateral_Movement/BASELINE%20-%20Lateral%20Movement%20-%20Possible%20Lateral%20Movement%20Through%20PSExec.yml), possa ser utilizada para detectar o comportamento produzido no dispositivo vítima, ao sofrer a exploração da ferramenta ***SMBExec***.

Também é possível observar outro comportamento, no qual além de dar *match* com a sequência de comportamentos produzidos pelo *PsExec*, também pode ser detectado por outra regra de detecção desenvolvida por meio de uma das pesquisas do *Purple Team*. Esta regra foi um output da pesquisa de [***Criação de Serviços Maliciosos no Windows***](https://github.com/ish-cti-purple/CTI-PurpleTeam/blob/main/Pesquisas/ATT%26CK%20TTPs/%5BTA0003%5D%20Persistence/%5BT1543%5D%20Create%20or%20Modify%20System%20Process/%5BT1543.003%5D%20Create%20or%20Modify%20System%20Process%3A%20Windows%20Service/CTI%20Purple%20Team%20-%20Cria%C3%A7%C3%A3o%20de%20Servi%C3%A7os%20Maliciosos%20no%20Windows/%5BCTI%20Purple%20Team%5D%20Cria%C3%A7%C3%A3o%20de%20Servi%C3%A7os%20Maliciosos%20no%20Windows.md).

Esta pesquisa nos permite compreender como podemos detectar a criação de serviços maliciosos por meio dos Event IDs [**7045**](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) e [**4697**](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697).

<p align="center">
  <img src="imagens/15.malicious_service_creation.png">
</p>

Foi implementado sa regra Sigma de todas as pesquisas citadas, e o resultado foi o match de cada aspecto da execução do ***SMBExec***.

<p align="center">
  <img src="imagens/14.ipc_write_data.png">
</p>

## Engenharia de Detecção

Para detectarmos a execução da ferramenta em PowerShell do SMBExec, nós confeccionamos a regra de detecção abaixo documentada no modelo Sigma.

```yaml
title: 000:1311431:000:TA0008.T1021.002:Possible Lateral Movement Through SMBExec
id: 77fba173-754b-4fdf-9271-3528648139fe
status: stable
description: 'Esta regra detecta o comportamento produzido pela execução do PSExec, para a realização de Movimentação Lateral.'
references:
    - 'https://attack.mitre.org/techniques/T1543/003'
    - 'https://attack.mitre.org/techniques/T1570/'
    - 'https://attack.mitre.org/techniques/T1021/002/'
    - 'https://attack.mitre.org/techniques/T1569/002/'
    - 'https://attack.mitre.org/techniques/T1550/002/'
author: CTI Purple Team
date: 2024/01/05
tags:
    - 'attack.persistence.T1543.003'
    - 'attack.lateral.movement.T1570'
    - 'attack.lateral.movement.T1021.002'
    - 'attack.execution.T1569.002'
    - 'attack.lateral.movement.T1550.002'
logsource:
    category: 'powershell_scriptblock_logging'
    product: 'windows'
detection:
    Message|contains:
        - '0xff,0x53,0x4d,0x42'
        - '0xfe,0x53,0x4d,0x42'
        - '0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00'
        - 'IPC$'
        - 'ADMIN$'
        - 'C$'
    condition: Message
fields:
    - PowerShell Script Block;
    - Computer Name.
falsepositives:
    - 'É necessário identificar realizar triagem de possíveis scripts que possam utilizar-se das mesmas capacidades, e que foram desenvolvidas pelos administradores de sistemas'
level: high
```

# Conclusão

Esperamos que você que leu ou assistiu o Webinar, possa ter compreendido a inteligência que trouxemos nesta pesquisa. Qualquer dúvida, é só nos contactar.

## Link do Webinar

Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link](https://ishtecnologia.sharepoint.com/sites/CTI-PurpleTeam/_layouts/15/stream.aspx?id=%2Fsites%2FCTI%2DPurpleTeam%2FDocumentos%20Compartilhados%2FVideos%2FCTI%20Purple%20Team%20%2D%20Movimenta%C3%A7%C3%A3o%20Lateral%20Atrav%C3%A9s%20do%20Invoke%2DSMBExec%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview).
