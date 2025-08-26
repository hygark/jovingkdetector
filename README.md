# jovingdetector


Aviso Importante: 
Voltado para auditorias de segurança autorizadas.
Este script é para uso educacional e em sistemas com permissão explícita. Uso não autorizado viola leis como o Código Penal Brasileiro (art. 154-A), LGPD, ou regulamentos internacionais (). Use com responsabilidade.


## Funcionalidades:

Escaneamento de Arquivos: Calcula hash SHA-256 (OpenSSL) e aplica regras YARA (libyara) para detectar malwares.
Análise de Malwares Polimórficos: Detecta ofuscação via cálculo de entropia (limite: 7.0).
Monitoramento de Processos: Identifica processos com uso elevado de CPU (GetProcessList no Windows, /proc no Linux, libproc no macOS, libprocstat no FreeBSD).
Detecção em Memória: Verifica padrões maliciosos na memória (ReadProcessMemory, /proc/[pid]/mem, task_for_pid, /proc/[pid]/map).
Verificação de Alterações:
Windows: Monitora alterações no registro (HKEY_LOCAL_MACHINE\\Run).
Linux/macOS/FreeBSD: Verifica modificações em arquivos críticos (ex.: /etc/passwd, /Library/Extensions, /boot/modules).


Detecção de Rede: Identifica conexões suspeitas (GetTcpTable, /proc/net, netstat).
Detecção de Rootkits: Verifica processos ocultos e alterações em drivers/módulos/kexts.
Relatórios JSON: Exporta resultados em JSON (logs/reports/) para análise.
Envio de Alertas: Suporta logging em arquivo, webhook (Discord), email (SMTP com libesmtp), Splunk (HEC), ELK (HTTP), e SIEM (eventos do Windows/syslog).
Interface Gráfica Expandida: Inclui botões (Iniciar/Parar/Exportar), gráficos de CPU/ameaças, e logs em tempo real (WinAPI, GTK, Cocoa).
Monitoramento de CPU: Pausa escaneamento se o uso de CPU exceder 80%.
Threading: Usa pthread para escaneamento contínuo, logging, e interface.

## Requisitos:

Compilador C: GCC (Windows: MinGW, baixe em mingw-w64.org; Linux: padrão; macOS: Xcode; FreeBSD: padrão).
Sistema Operacional: Windows 10/11, Linux (ex.: Ubuntu 24.04), macOS (ex.: Sonoma 14), FreeBSD (ex.: 14.0).
Dependências:
Windows: windows.h, iphlpapi.h (Windows SDK), libcurl, OpenSSL, json-c, libesmtp, libyara.
Linux: libcurl, OpenSSL, json-c, libesmtp, libyara, libgtk-3-dev.
macOS: libproc, Cocoa, libcurl, OpenSSL, json-c, libesmtp, libyara.
FreeBSD: libprocstat, libcurl, OpenSSL, json-c, libesmtp, libyara, gtk3.


Estrutura do Ambiente: Máquina Windows/Linux/macOS/FreeBSD com permissão para testes de segurança.
Bibliotecas:
Windows: Instale libcurl, OpenSSL, json-c, libesmtp, libyara.
Linux: sudo apt install libcurl4-openssl-dev libssl-dev libjson-c-dev libesmtp-dev libyara-dev libgtk-3-dev.
macOS: brew install libcurl openssl json-c libesmtp yara.
FreeBSD: pkg install libcurl openssl json-c libesmtp yara gtk3.



## Instalação:

Crie um Repositório no GitHub (opcional para versionamento):
Vá para github.com e crie um novo repositório chamado "MalwareDetector".
Clone o repo: git clone https://github.com/hygark/MalwareDetector.git.


Adicione o Script:
Copie o conteúdo de MalwareDetector.c para um arquivo C no seu diretório.


## Instale Dependências:

Windows:
Instale MinGW: mingw-w64.org.
Instale libcurl, OpenSSL, json-c, libesmtp, libyara (ex.: mingw-get install libcurl libssl json-c libesmtp libyara).


Linux:
Instale pacotes: sudo apt update && sudo apt install libcurl4-openssl-dev libssl-dev libjson-c-dev libesmtp-dev libyara-dev libgtk-3-dev.


macOS:
Instale Homebrew: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)".
Instale pacotes: brew install libcurl openssl json-c libesmtp yara.


FreeBSD:
Instale pacotes: sudo pkg install libcurl openssl json-c libesmtp yara gtk3.




## Compile o Programa:
Windows: gcc -o malware_detector MalwareDetector.c -lws2_32 -lcurl -lcrypto -liphlpapi -ljson-c -lesmtp -lyara.
Linux: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread.
macOS: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -framework Cocoa.
FreeBSD: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread.



## Configuração no C:

Abra o script e edite as definições no início:

SCAN_DIR: Diretório para escaneamento (padrão: scan/).
REPORT_DIR: Diretório para relatórios JSON (padrão: logs/reports/).
LOG_FILE: Arquivo de log (padrão: logs/malware_detector.log).
YARA_RULES: Arquivo com regras YARA (padrão: rules.yar).
SIGNATURES_FILE: Arquivo com assinaturas SHA-256 (padrão: signatures.txt).
WEBHOOK_URL: URL de um webhook Discord (crie em Discord > Server Settings > Integrations).
SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN: URL e token do Splunk HEC (configure no Splunk).
ELK_URL: URL do ELK (ex.: http://localhost:9200/_bulk).
SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_TO: Configurações para envio de email (ex.: Gmail com senha de app).
SCAN_INTERVAL: Intervalo de escaneamento (padrão: 60 segundos).
MAX_LOG_SIZE: Tamanho máximo do buffer de log (padrão: 16384 bytes).
CPU_THRESHOLD: Limite de uso de CPU (padrão: 80%).
MEMORY_PATTERN: Padrão para detecção em memória (padrão: malware).
ENTROPY_THRESHOLD: Limite de entropia para malwares polimórficos (padrão: 7.0).


Crie arquivos signatures.txt (ex.: d41d8cd98f00b204e9800998ecf8427e) e rules.yar (ex.: rule TestRule { strings: $a = "malware" condition: $a }).

Ajuste as Configurações:
Edite as definições no script (ex.: WEBHOOK_URL, SPLUNK_*, ELK_URL, SMTP_*, SCAN_DIR, YARA_RULES).
Para Gmail, crie uma senha de aplicativo em myaccount.google.com > Security > 2-Step Verification > App Passwords.
Para Splunk, configure o HTTP Event Collector em splunk.com e obtenha SPLUNK_HEC_URL e SPLUNK_HEC_TOKEN.
Para ELK, configure o endpoint HTTP em elastic.co (ex.: http://localhost:9200/_bulk).


## Compile e Execute:
Windows: gcc -o malware_detector MalwareDetector.c -lws2_32 -lcurl -lcrypto -liphlpapi -ljson-c -lesmtp -lyara && ./malware_detector.
Linux: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread && ./malware_detector.
macOS: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -framework Cocoa && ./malware_detector.
FreeBSD: gcc -o malware_detector MalwareDetector.c -lcurl -lcrypto -ljson-c -lesmtp -lyara -lgtk-3 -pthread && ./malware_detector.


Teste:
Coloque arquivos de teste em scan/ e adicione hashes/regras em signatures.txt/rules.yar.
Execute em uma máquina Windows/Linux/macOS/FreeBSD autorizada.
Verifique logs em logs/malware_detector.log, relatórios JSON em logs/reports/, e alertas via webhook/email/Splunk/ELK/SIEM.
Interaja com a GUI (botões Iniciar/Parar/Exportar, gráficos de CPU).
Pressione qualquer tecla (CLI) ou feche a janela (GUI) para parar.


Parar o Programa:
Pressione qualquer tecla no terminal ou use o botão "Parar" na GUI.



## Exemplos de Uso:

Escaneamento Local: Execute para detectar arquivos maliciosos, malwares polimórficos, processos suspeitos, malwares em memória, rootkits, e alterações no sistema via GUI/CLI.
Monitoramento Remoto: Configure webhook (Discord), SMTP (Gmail), Splunk (HEC), ELK (HTTP), e SIEM para alertas em tempo real.
Análise de Relatórios: Use os arquivos JSON em logs/reports/ para análise detalhada.
Expansão: Adicione suporte a detecção de exploits, integração com QRadar, ou análise de tráfego de rede.

Aviso Legal e Ético:

Este script é para fins educativos e testes em sistemas com permissão explícita. Uso não autorizado viola leis como o Código Penal Brasileiro (art. 154-A), LGPD, ou regulamentos internacionais ().
Sempre obtenha autorização por escrito antes de usar em qualquer sistema.
Use em ambientes controlados (ex.: máquina local com permissão) para auditorias de segurança.
