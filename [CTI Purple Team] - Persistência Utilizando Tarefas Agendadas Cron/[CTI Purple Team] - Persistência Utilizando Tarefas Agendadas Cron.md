
<p align="center">
  <img src="./Imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Persistência Utilizando Tarefas Agendadas Cron

Nesta pesquisa, iremos abordar a tática [TA0003](https://attack.mitre.org/tactics/TA0003/) (Persistência), dando ênfase a sub-técnica [T1053.003](https://attack.mitre.org/techniques/T1053/003/) (Scheduled Task/Job: Cron).

Assim que temos acesso a um sistema comprometido, existem algumas maneiras de aumentar sua posição no sistema para acesso de retorno futuro, também conhecido como persistência. Isso serve como um caminho de volta caso o sistema seja atualizado ou corrigido, tornando inútil o caminho de entrada original explorado. 

A persistência pode ser feita de várias maneiras e com vários métodos, mas hoje neste guia explicaremos como podemos aproveitar as vantagens do **Cron** para usar cron jobs (tarefas agendadas) para criar mais uma camada de persistência usando um backdoor programado.

`Cron` é um daemon de agendamento de tarefas baseado em tempo encontrado em sistemas operacionais do tipo Unix, incluindo distribuições Linux. O Cron é executado em segundo plano e as operações agendadas com cron, chamadas de “cron jobs”, são executadas automaticamente, tornando o cron útil para automatizar tarefas relacionadas à manutenção.

Este guia fornece uma visão geral de como agendar tarefas usando a sintaxe especial do cron. Também aborda alguns atalhos que você pode usar para agilizar o processo de redação de cronogramas de trabalho e torná-los mais compreensíveis.

**A priori, para executar a manipulação de conta, é importante salientar que o atacante já possua o primeiro acesso inicial à máquina alvo, com privilégios administrativos. Portando, já ter realizado a Execução e Escalação de Privilégios na vítima**.

## Contexto

Um ***Cron Job*** é um programa Linux que permite aos usuários agendar a execução de um software, geralmente na forma de um `script shell` ou de um `executável compilado`. Cron normalmente é usado quando você tem uma tarefa que precisa ser executada em um cronograma fixo e/ou para automatizar tarefas repetitivas, como download de arquivos ou envio de e-mails, backups.

A maioria das instalações padrão do cron consiste em dois comandos: ***`cron`*** ou ***`crond`***, que é o daemon que executa o utilitário de agendamento ***`crontab`***, que é o comando que permite editar as entradas cron para seus trabalhos

O Cron é um `daemon`, isso significa que ele trabalha em segundo plano para executar tarefas não-interativas. Isso significa que o programa não  aceita nenhuma entrada do usuário e não exibe a saída para o usuário. No Windows, você pode estar mais familiarizados com processos em plano de fundo com os Serviços.  O daemon cron ( crond ) procura entradas no crontab para determinar quais tarefas ele deve executar e quando deve executá-las de acordo com o agendamento especificado. 

Um daemon está sempre no status ocioso e aguarda uma solicitação de um comando para desempenhar uma certa tarefa. Essa tarefa pode ser tanto de dentro do computador principal quanto de qualquer outra máquina conectada à mesma rede.

Em seu nível mais básico, um cron job é uma entrada escrita em uma tabela chamada `tabela cron`, também conhecida como `crontab`. Esta entrada contém uma programação e um comando a ser executado. O sistema padrão do arquivo contab é `/etc/crontab` e ele fica localizado dentro do diretório crontab, que é `/etc/cron.*/`. 

Apenas administradores podem editar um arquivo crontab do sistema. Porém, como os sistemas operacionais Unix têm suporte a múltiplos usuários, cada um pode criar seu próprio arquivo crontab e lançar comandos para executar tarefas em qualquer hora que eles quiserem. Um daemon Cron vai verificar o arquivo e rodar o comando no plano de fundo do sistema.

## Etapa I: Compreendendo como funciona o Cron

Os trabalhos Cron são registrados e gerenciados em um arquivo especial conhecido como crontab. Cada perfil de usuário no sistema pode ter seu próprio crontab local onde pode agendar trabalhos, que é armazenado em `/var/spool/cron/crontabs/`.

Para agendar um trabalho, abra-o `crontab` para edição e adicione uma tarefa escrita na forma de uma expressão ***cron*** . A sintaxe das expressões cron pode ser dividida em dois elementos: `o agendamento e o comando a ser executado`.

O comando pode ser praticamente qualquer comando que você normalmente executaria na linha de comando. O componente de agendamento da sintaxe é dividido em 5 campos diferentes, que são escritos na seguinte ordem:



<center>

| Campos de Agendamento          | Descrição                                                              |
|--------------------------------|------------------------------------------------------------------------|
| MINUTE (Minuto)                | Minuto da hora em que o comando será executado, variando de `0 a 59`   |
| HOUR (Hora)                    | Hora em que o comando será executado, variando de `0 a 23`             |
| DAY OF THE MONTH (Dia do Mês)  | Dia do mês em que o comando vai rodar, variando de `1 a 31`            |
| MONTH (Mês)                    | Mês em que o comando será executado, variando de `1 a 12`              |
| DAY OF THE WEEK (Dia da Semana)| Dia da semana que você quer que o comando execute, variando de `0 a 6`.|  

***`info: a semana se inicia no domingo, sendo o valor 0`***

</center>

Juntas, as tarefas agendadas em um crontab são estruturadas da seguinte forma:

`minute` `hour` `day_of_month` `month` `day_of_week` `command_to_run`

Aqui está um exemplo funcional de uma expressão cron. Esta expressão executa o comando `curl http://www.google.com` toda terça-feira às 17h30:

```zsh
30 17 * * 2 curl http://www.google.com
``` 


```bash
30   17   *    *    2    curl http://www.google.com
|    |    |    |    |            |
|    |    |    |    |    Command or Script to execute
|    |    |    |    |
|    |    |    | Day of the week(0-6 | Sun-Sat)
|    |    |    |
|    |    |  Month(1-12)
|    |    |
|    |  Day of Month(1-31)
|    |
|   Hour(0-23)
|
Min(0-59)
```

Existem também alguns caracteres especiais que você pode incluir no componente de agendamento de uma expressão cron para agilizar tarefas de agendamento:

- **Asterisco** `(*)`: Em expressões cron, um asterisco é uma variável curinga que representa **“todos”**. 
  - **Ex:** Uma tarefa agendada com `* * * * * ...` será executada a cada minuto de cada hora de cada dia de cada mês.
- **Vígula** `(,)`: As vírgulas separam os valores de agendamento para formar uma lista. 
  - **Ex:** Se você quiser que uma tarefa seja executada no início e no meio de cada hora, em vez de escrever duas tarefas separadas (por exemplo, `0 * * * * ...` e `30 * * * * ...`), você poderá obter a mesma funcionalidade com uma (`0,30 * * * * ...`).
- **Hífen** `(-)`: Um hífen representa um intervalo de valores no campo de agendamento.
  - **Ex:** Em vez de ter 30 tarefas agendadas separadas para um comando que você deseja executar nos primeiros 30 minutos de cada hora (como em `0 * * * * ...`, `1 * * * * ...`, `2 * * * * ...` e assim por diante), você pode agendá-lo como `0-29 * * * * ...`.
- **Barra inclinada** `(/)`: Pode-se usar uma barra com um asterisco para expressar um valor de etapa. 
  - **Ex:** Em vez de escrever oito tarefas cron separadas para executar um comando a cada três horas (como em, `0 0 * * * ...`, `0 3 * * * ...`, `0 6 * * * ...` e assim por diante), você pode agendá-lo para ser executado assim: `0 */3 * * * ...`.

Aqui estão mais alguns exemplos de como usar o componente de agendamento do cron:

- `* * * * *` - Execute o comando a cada minuto.
- `12 * * * *` - Execute o comando 12 minutos após cada hora.
- `0,15,30,45 * * * *` - Execute o comando a cada 15 minutos.
- `*/15 * * * *` - Execute o comando a cada 15 minutos.
- `0 4 * * *` - Execute o comando todos os dias às 4h.
- `0 4 * * 2-4` - Execute o comando todas as terças, quartas e quintas às 4h.
- `20,40 */8 * 7-12 *` - Execute o comando nos 20 e 40 minutos de cada 8 horas todos os dias dos últimos 6 meses do ano.

Se você achar isso confuso ou se quiser ajuda para escrever cronogramas para suas próprias cron tarefas, o [Cronitor](https://cronitor.io/) fornece um prático croneditor de expressões de cronograma chamado [“Crontab Guru”](https://crontab.guru/) que você pode usar para verificar se seus croncronogramas são válidos.

Antes de continuar, tenha em mente que a saída do comando vai automaticamente ser enviada para sua conta de email local. Então, se você quer parar de receber esses emails, você pode adicionar `>/dev/null 2>&1` à sintaxe. Como no exemplo:

```zsh
0 5 * * * /root/backup.sh >/dev/null 2>&1
``` 

Além disso, se você quer receber a saída de email em uma conta específica, então você pode adicionar MAILTO, seguido do endereço de email. Aqui está um exemplo:

```zsh
MAILTO="username@ish.com.br"
0 3 * * * /root/backup.sh >/dev/null 2>&1
``` 

## Etapa II: Instalando e Habilitando o Cron

Quase todas as distribuições Linux têm algum tipo de cron instalado por padrão. O daemon estará rodando sob o usuário ***root***. No entanto, se você estiver usando uma máquina Ubuntu que cron não esteja instalada, poderá instalá-la usando o APT.

Você pode executar o seguinte comando para ver se o cron está em execução:

```zsh
ps aux | grep cron
``` 

Você deverá ver uma saída como esta:

<p align="center">
  <img src="Imagens/cron em execução.png">
  <br>
  Figura 1: Saída do Cron em Execução
</p>

Se você não recebeu nenhuma saída do comando, o cron não está em execução ou não está instalado. Antes de instalar o cron em uma máquina Ubuntu, atualize o índice de pacotes local do computador:

```zsh
sudo apt update
``` 

Em seguida, instale `cron` com o seguinte comando:

```zsh
sudo apt install cron
``` 

***`Info:`*** `Se estiver usando algo diferente do Ubuntu, você precisará executar o comando equivalente para o seu gerenciador de pacotes.`

Após a instalação, você precisará certificar-se de que ele também esteja ativo e configurado para execução em segundo plano, usando o comando `systemctl` fornecido pelo systemd:

```zsh
sudo systemctl enable cron
``` 

<p align="center">
  <img src="Imagens/habilitando cron em segundo plano.png">
  <br>
  Figura 2: Habilitando o Cron em Segundo Plano
</p>

Em seguida, cron estará instalado em seu sistema e pronto para você iniciar o agendamento de jobs.

## Emulação de Ameaça - Criar o Script Shell e a Cron job

Como vimos anteriormente, uma tarefa agendada cron pode ser criada com qualquer script ou comando que seja executável na linha de comando. Sendo assim, depois de ter compreendido a funcionalidade e a criação dos cronjobs, nesta emulação de ataque iremos representar o agendamento de um script shell contendo comandos para executar um shell reverso na máquina do atacante a cada minuto todas as horas de todos os dias e meses, a fim de mantermos persistência, mesmo que o sitema seja atualizado ou reinicializado.

### 1. Criando Script Shell

Depois de instalado e habilitado o cron, crie um script shell que contenha os comandos necessários para estabelecer a conexão de shell reverso. 

Abra um terminal e use um editor de texto como `nano, vi, ou vim` para criar um novo arquivo de script. Por exemplo, usando o nano:

```zsh
nano reverseshell.sh
``` 

Digite o conteúdo do script no editor. Aqui está um exemplo básico que escreve uma mensagem em um arquivo de log e cria o shell reverso para nosso ataque:

<p align="center">
  <img src="Imagens/script shell do shell reverso.png">
  <br>
  Figura 3: Conteúdo do Script Shell para a Shell Reverso
</p>

Se você estiver usando o nano, salve e saia pressionando `Ctrl+O`, depois `Enter` para salvar e `Ctrl+X` para sair.

Altere as permissões do arquivo para torná-lo executável:

```zsh
chmod +x reverseshell.sh
``` 

Execute o script manualmente para iniciá-lo:

```zsh
./reverseshell.sh &
``` 

Você deve ver algo como:

<p align="center">
  <img src="Imagens/executando script manualmente.png">
  <br>
  Figura 4: Executando Script Shell Manualmente
</p>

Agora que o script está pronto, você pode configurá-lo para ser executado a cada minuto usando o cron. 

### 2. Criando Cron job

Depois de definir um cronograma e saber o trabalho que deseja executar, você precisará colocá-lo em algum lugar onde seu daemon possa lê-lo.

Conforme mencionado anteriormente, a `crontab` é um arquivo especial que contém o agendamento dos trabalhos cron que serão executados. No entanto, estes não se destinam a ser editados diretamente. Em vez disso, é recomendado que você use o comando crontab. Isso permite que você edite seu perfil de usuário crontab sem alterar seus privilégios com `sudo`. O comando `crontab` também informará se você tiver erros de sintaxe no arquivo crontab, mas editá-lo diretamente não.

Você pode editar seu crontab com o seguinte comando:

```zsh
crontab -e
``` 

Se esta for a primeira vez que você executa o comando `crontab -e` neste perfil de usuário, ele solicitará que você selecione um editor de texto padrão para usar ao editar seu arquivo crontab:

<p align="center">
  <img src="Imagens/primeira execução  crontab.png">
  <br>
  Figura 5: Primeira Execução do Crontab neste Usuário
</p>

Digite o número correspondente ao editor de sua preferência. Alternativamente, você pode pressionar `ENTER` para aceitar a escolha padrão, `nano`.

Depois de fazer sua seleção, você será levado a um novo crontab contendo algumas instruções comentadas sobre como usá-lo:

<p align="center">
  <img src="Imagens/informações do crontab.png">
  <br>
  Figura 6: Instruções Comentadas do Crontab
</p>

Se você quer editar um crontab de outro usuário, você pode digitar `crontab -u username -e`. Tenha em mente que você só pode fazer isso como um **superusuário**. Isso significa que você precisa digitar `sudo su` antes de digitar o comando.

Quando você executar `crontab -e` no futuro, seu `crontab` editor de texto será exibido automaticamente. Uma vez no editor, você pode inserir sua programação com cada trabalho em uma nova linha. Caso contrário, você pode salvar e fechar o crontab por enquanto (`CTRL + O e ENTER` para salvar e `CTRL + X` para fechar, se tiver selecionado nano).

Agora vamos adicionar a seguinte linha ao crontab para executar o script shell que criamos anteriormente a cada minuto em segundo plano:

```zsh
* * * * * reverseshell.sh >/dev/null 2>&1 &
``` 

Para verificar se o cron job foi adicionado corretamente, mas não modificá-lo, pode-se usar o comando abaixo:

```zsh
crontab -l
``` 

<p align="center">
  <img src="Imagens/lista de agendamentos cron.png">
  <br>
  Figura 7: verificando Crontabs Criados
</p>

Verifique também o arquivo de log para garantir que o script está sendo executado conforme esperado, substitua o caminho do exemplo abaixo pelo caminho exato do log gerado quando criamos o script shell:

```zsh
tail -f /path/to/logfile.log
``` 

<p align="center">
  <img src="Imagens/logs do script shell.png">
  <br>
  Figura 7: Virificando Arquivo de Log do Script Criado
</p>

Após ter sido configurado com êxito a crontab, neste momento podemos na máquina atacante executar o listener, utilizando o NetCat, para escutar qualquer conexão atruibuída na porta TCP/6789 escolhida ppara nosso shell reverso:

```zsh
nc -nvlp 6789 
``` 

A partir disso, quando o cron executar nosso script, o shell reverso será conectado automaticamente na porta em escuta na máquina atacante:

<p align="center">
  <img src="Imagens/conexão shell reverso.png">
  <br>
  Figura 7: Obtendo a Conexão com o Shell Reverso
</p>

## Engenharia de Detecção

Como podemos observar o Cron é a forma mais tradicional de criar tarefas agendadas. Os diretórios interessantes para nós são os seguintes:

- /etc/crontab/
- /etc/cron.d/
- /etc/cron.{hourly,daily,weekly,monthly}/
- /var/spool/cron/
- /etc/cron.allow
- /etc/cron.deny

A partir de nossa referência do arquivo de configuração do [Auditd]() para Linux, o documento nos fornecem as seguintes regras para monitorar logs do Cron:

<p align="center">
  <img src="Imagens/auditd rules.png">
  <br>
  Figura 8: Regras do Arquivo de Configuração Auditd para Linux
</p>

Quando uma modificação ocorre no arquivo **/etc/crontab/**, o Auditd registra os seguintes logs:

<p align="center">
  <img src="Imagens/logs do crontab do sistema.png">
  <br>
  Figura 9: Logs gerados Após Modificação do Cron do Sistema
</p>

Agora quando a modificação é feita diretamente no crontab do usuário específico, utilizando o comando **crontab -e**, o Auditd registra os logs abaixo:

<p align="center">
  <img src="Imagens/logs do crontab do usuario.png">
  <br>
  Figura 9: Logs gerados Após Modificação do Cron do Usuário
</p>

Abaixo é demonstrado a regra criada no Elastic para detecção do log de alteração do arquivo `crontab` e seus alertas gerados:

<p align="center">
  <img src="Imagens/Regra gerando alertas.png">
  <br>
  Figura 10: Alertas Gerados com a Regra Criada pelo Purple Team
</p>

### Padrão SIGMA: Account Manipulation: SSH Authorized Keys

```yaml
title: 'Linux - Persistência Utilizando Tarefas Agendadas Cron - BASELINE'
id: edc14135-1567-4366-85a9-37afb55a7e33
status: stable
description: 'Esta regra detecta o comportamento gerado pela criação de tarefas agendadas cron'
references:
    - 'https://attack.mitre.org/techniques/T1053/003/'
author: CTI Purple Team - Bryenne Soares
date: 28/06/2024
tags:
    - attack.persistence.TA0003
    - attack.T1053.003 # Scheduled Task/Job: Cron
logsource:
    category: 
    product: Linux
    definition: auditd
detection: 
    Process_Creation: 

    condition: 
fields:
    -
falsepositives:
    - "É necessário validar se foi realizado uma ação administrativa de conhecimento da equipe de infraestrutura"
level: high
```

## Conclusão

Esperamos que você que leu ou assistiu o Webinar, possa ter compreendido a inteligência que trouxemos nesta pesquisa. Qualquer dúvida, é só nos contactar.

## Link do Webinar

Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link]()

