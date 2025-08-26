#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <yara.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#elif defined(__APPLE__)
#include <libproc.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <objc/objc.h>
#include <objc/runtime.h>
#include <Cocoa/Cocoa.h>
#elif defined(__FreeBSD__)
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gtk/gtk.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gtk/gtk.h>
#endif

#include <esmtp.h>
// hygark, sempre há algo nos observando.
// Configurações personalizáveis
#define SCAN_DIR "scan/" // Diretório para escaneamento
#define REPORT_DIR "logs/reports/" // Diretório para relatórios JSON
#define LOG_FILE "logs/malware_detector.log" // Arquivo de log
#define YARA_RULES "rules.yar" // Arquivo com regras YARA
#define SIGNATURES_FILE "signatures.txt" // Arquivo com assinaturas SHA-256
#define WEBHOOK_URL "" // URL de webhook (ex.: Discord)
#define SPLUNK_HEC_URL "" // URL do Splunk HTTP Event Collector
#define SPLUNK_HEC_TOKEN "" // Token do Splunk HEC
#define ELK_URL "" // URL do ELK (ex.: http://localhost:9200/_bulk)
#define SMTP_SERVER "smtp.gmail.com" // Servidor SMTP
#define SMTP_PORT 587 // Porta SMTP
#define SMTP_USER "" // Usuário SMTP (ex.: seuemail@gmail.com)
#define SMTP_PASS "" // Senha SMTP (ex.: senha de app do Gmail)
#define SMTP_TO "" // Destinatário do email
#define SCAN_INTERVAL 60 // Intervalo de escaneamento (segundos)
#define MAX_LOG_SIZE 16384 // Tamanho máximo do buffer de log
#define CPU_THRESHOLD 80 // Limite de uso de CPU (%)
#define MEMORY_PATTERN "malware" // Padrão de exemplo para detecção em memória
#define ENTROPY_THRESHOLD 7.0 // Limite de entropia para malwares polimórficos

// Estado do programa
typedef struct {
    int is_running;
    int total_files_scanned;
    int total_malwares_detected;
    int total_processes_scanned;
    int total_rootkits_detected;
    int total_memory_threats;
    int total_polymorphic_detected;
    char log_buffer[MAX_LOG_SIZE];
    json_object *report_json;
    #ifdef _WIN32
    HWND hwnd, hStartBtn, hStopBtn, hExportBtn, hText, hGraph;
    #elif defined(__APPLE__)
    id window, startBtn, stopBtn, exportBtn, textView;
    #else
    GtkWidget *window, *start_btn, *stop_btn, *export_btn, *text_view, *graph_area;
    #endif
} ScriptState;

ScriptState state = {0, 0, 0, 0, 0, 0, 0, {0}, NULL};

// Função para calcular entropia (detecção de malwares polimórficos)
double calculate_entropy(const unsigned char *data, size_t len) {
    double entropy = 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

// Função para calcular hash SHA-256
void calculate_sha256(const char *path, unsigned char *output) {
    FILE *file = fopen(path, "rb");
    if (!file) return;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes);
    }
    SHA256_Final(output, &sha256);
    fclose(file);
}

// Função para verificar assinaturas SHA-256
int check_signature(const char *hash) {
    FILE *sig_file = fopen(SIGNATURES_FILE, "r");
    if (!sig_file) return 0;

    char line[256];
    while (fgets(line, sizeof(line), sig_file)) {
        line[strcspn(line, "\n")] = 0;
        if (strcmp(line, hash) == 0) {
            fclose(sig_file);
            return 1;
        }
    }
    fclose(sig_file);
    return 0;
}

// Função para verificar regras YARA
int check_yara(const char *file_path) {
    yr_initialize();
    yr_compiler *compiler = NULL;
    yr_rules *rules = NULL;
    int result = 0;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return 0;
    FILE *rule_file = fopen(YARA_RULES, "r");
    if (!rule_file) {
        yr_compiler_destroy(compiler);
        return 0;
    }

    if (yr_compiler_add_file(compiler, rule_file, NULL, NULL) != 0) {
        fclose(rule_file);
        yr_compiler_destroy(compiler);
        return 0;
    }
    fclose(rule_file);

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return 0;
    }

    int matches = 0;
    yr_rules_scan_file(rules, file_path, SCAN_FLAGS_FAST_MODE, NULL, &matches, 0);
    if (matches > 0) result = 1;

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    return result;
}

// Função para inicializar JSON
void init_json_report() {
    state.report_json = json_object_new_object();
    json_object *events = json_object_new_array();
    json_object_object_add(state.report_json, "events", events);
}

// Função para adicionar evento ao JSON
void add_json_event(const char *type, const char *details) {
    json_object *event = json_object_new_object();
    json_object_object_add(event, "type", json_object_new_string(type));
    json_object_object_add(event, "details", json_object_new_string(details));
    json_object_object_add(event, "timestamp", json_object_new_string(ctime(&time(NULL))));
    json_object_array_add(json_object_object_get(state.report_json, "events"), event);
}

// Função para salvar relatório JSON
void save_json_report() {
    #ifdef _WIN32
    CreateDirectory(REPORT_DIR, NULL);
    #else
    mkdir(REPORT_DIR, 0777);
    #endif
    char filename[256];
    snprintf(filename, sizeof(filename), "%sreport_%ld.json", REPORT_DIR, time(NULL));
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "%s", json_object_to_json_string_ext(state.report_json, JSON_C_TO_STRING_PRETTY));
        fclose(fp);
        char msg[512];
        snprintf(msg, sizeof(msg), "Relatório JSON salvo em %s", filename);
        log_message("INFO", msg);
    }
}

// Função para verificar uso de CPU
int check_cpu_usage() {
    #ifdef _WIN32
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        ULONGLONG total = kernelTime.dwLowDateTime + userTime.dwLowDateTime;
        ULONGLONG idle = idleTime.dwLowDateTime;
        return (total > 0) ? (100 - (idle * 100 / total)) : 0;
    }
    #elif defined(__APPLE__)
    FILE *fp = popen("top -l 1 | grep 'CPU usage' | awk '{print $3}'", "r");
    if (!fp) return 0;
    float cpu;
    fscanf(fp, "%f", &cpu);
    pclose(fp);
    return (int)cpu;
    #elif defined(__FreeBSD__)
    FILE *fp = popen("top -b 1 | grep 'CPU:' | awk '{print $2}'", "r");
    if (!fp) return 0;
    float cpu;
    fscanf(fp, "%f", &cpu);
    pclose(fp);
    return (int)cpu;
    #else
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return 0;
    long user, nice, system, idle;
    fscanf(fp, "cpu %ld %ld %ld %ld", &user, &nice, &system, &idle);
    fclose(fp);
    long total = user + nice + system + idle;
    return (total > 0) ? (100 - (idle * 100 / total)) : 0;
    #endif
    return 0;
}

// Função para enviar logs (arquivo, webhook, email, Splunk, ELK, SIEM)
void log_message(const char *level, const char *message) {
    // Log em arquivo
    #ifdef _WIN32
    CreateDirectory("logs", NULL);
    #else
    mkdir("logs", 0777);
    #endif
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        fprintf(log_file, "[%s] [%s] %s\n", level, ctime(&now), message);
        fclose(log_file);
    }

    // Log via webhook
    if (strlen(WEBHOOK_URL) > 0) {
        CURL *curl = curl_easy_init();
        if (curl) {
            char payload[512];
            snprintf(payload, sizeof(payload), "{\"content\": \"[%s] MalwareDetector: %s\"}", level, message);
            curl_easy_setopt(curl, CURLOPT_URL, WEBHOOK_URL);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
    }

    // Log via Splunk HEC
    if (strlen(SPLUNK_HEC_URL) > 0 && strlen(SPLUNK_HEC_TOKEN) > 0) {
        CURL *curl = curl_easy_init();
        if (curl) {
            char payload[512];
            snprintf(payload, sizeof(payload), "{\"event\": {\"level\": \"%s\", \"message\": \"%s\", \"time\": %ld}}",
                     level, message, time(NULL));
            struct curl_slist *headers = NULL;
            char auth_header[256];
            snprintf(auth_header, sizeof(auth_header), "Authorization: Splunk %s", SPLUNK_HEC_TOKEN);
            headers = curl_slist_append(headers, auth_header);
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_URL, SPLUNK_HEC_URL);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_perform(curl);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    }

    // Log via ELK
    if (strlen(ELK_URL) > 0) {
        CURL *curl = curl_easy_init();
        if (curl) {
            char payload[512];
            snprintf(payload, sizeof(payload), "{\"index\":{}}\n{\"level\": \"%s\", \"message\": \"%s\", \"time\": %ld}\n",
                     level, message, time(NULL));
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
            curl_easy_setopt(curl, CURLOPT_URL, ELK_URL);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_perform(curl);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    }

    // Log via email
    if (strlen(SMTP_SERVER) > 0 && strlen(SMTP_USER) > 0 && strlen(SMTP_TO) > 0) {
        smtp_t smtp = smtp_create();
        if (smtp) {
            smtp_set_server(smtp, SMTP_SERVER, SMTP_PORT);
            smtp_set_auth(smtp, SMTP_USER, SMTP_PASS);
            smtp_set_message(smtp, SMTP_TO, "MalwareDetector Alert", message);
            smtp_send(smtp);
            smtp_destroy(smtp);
            char msg[512];
            snprintf(msg, sizeof(msg), "Alerta enviado por email para %s", SMTP_TO);
            printf("[INFO] [%s] %s\n", ctime(&now), msg);
        }
    }

    // Log para SIEM
    #ifdef _WIN32
    HANDLE hEventLog = RegisterEventSource(NULL, "MalwareDetector");
    if (hEventLog) {
        const char *strings[] = {message, NULL};
        ReportEvent(hEventLog, strcmp(level, "ALERT") == 0 ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE,
                    0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
    #else
    openlog("MalwareDetector", LOG_PID, LOG_USER);
    syslog(strcmp(level, "ALERT") == 0 ? LOG_ERR : LOG_INFO, "%s", message);
    closelog();
    #endif

    // Adicionar ao relatório JSON
    add_json_event(level, message);

    // Atualizar GUI
    char gui_msg[512];
    snprintf(gui_msg, sizeof(gui_msg), "[%s] %s\n", level, message);
    #ifdef _WIN32
    if (state.hText) {
        char current[1024];
        GetWindowText(state.hText, current, sizeof(current));
        strncat(current, gui_msg, sizeof(current) - strlen(current) - 1);
        SetWindowText(state.hText, current);
    }
    #elif defined(__APPLE__)
    if (state.textView) {
        @autoreleasepool {
            NSTextView *textView = state.textView;
            NSString *newText = [NSString stringWithFormat:@"%s%@", [textView string], @(gui_msg)];
            [textView setString:newText];
        }
    }
    #else
    if (state.text_view) {
        GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(state.text_view));
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_buffer_insert(buffer, &end, gui_msg, -1);
    }
    #endif

    printf("[INFO] [%s] %s\n", ctime(&now), message);
}

#ifdef _WIN32
// Função para detecção em memória (Windows)
void scan_memory() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            char buffer[1024];
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)0x1000000, buffer, sizeof(buffer), &bytesRead)) {
                if (strstr(buffer, MEMORY_PATTERN)) {
                    state.total_memory_threats++;
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Malware em memória detectado: %s (PID: %lu)", pe32.szExeFile, pe32.th32ProcessID);
                    log_message("ALERT", msg);
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

// Função para detectar rootkits (Windows)
void detect_rootkits() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) {
            state.total_rootkits_detected++;
            char msg[512];
            snprintf(msg, sizeof(msg), "Rootkit potencial detectado: Processo oculto (PID: %lu)", pe32.th32ProcessID);
            log_message("ALERT", msg);
        } else {
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

// Função para escanear processos (Windows)
void scan_processes() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        log_message("ERROR", "Falha ao obter lista de processos");
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        state.total_processes_scanned++;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            FILETIME create, exit, kernel, user;
            GetProcessTimes(hProcess, &create, &exit, &kernel, &user);
            ULONGLONG total_time = kernel.dwLowDateTime + user.dwLowDateTime;
            if (total_time > 10000000) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Processo suspeito detectado: %s (PID: %lu)", pe32.szExeFile, pe32.th32ProcessID);
                log_message("WARNING", msg);
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

// Função para verificar alterações no registro (Windows)
void check_registry_changes() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, NULL, NULL, NULL, (BYTE *)value, &size) == ERROR_SUCCESS) {
            char msg[512];
            snprintf(msg, sizeof(msg), "Alteração detectada no registro: %s", value);
            log_message("WARNING", msg);
        }
        RegCloseKey(hKey);
    }
}

// Função para verificar conexões de rede (Windows)
void check_network_connections() {
    PMIB_TCPTABLE pTcpTable;
    DWORD size = 0;
    GetTcpTable(NULL, &size, TRUE);
    pTcpTable = (PMIB_TCPTABLE)malloc(size);
    if (GetTcpTable(pTcpTable, &size, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            char remote_addr[16];
            sprintf(remote_addr, "%s", inet_ntoa(*(struct in_addr *)&pTcpTable->table[i].dwRemoteAddr));
            if (strcmp(remote_addr, "0.0.0.0") != 0) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Conexão suspeita detectada: %s:%lu", remote_addr, pTcpTable->table[i].dwRemotePort);
                log_message("WARNING", msg);
            }
        }
    }
    free(pTcpTable);
}

// Função para interface gráfica (Windows)
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            state.hStartBtn = CreateWindow("BUTTON", "Iniciar", WS_CHILD | WS_VISIBLE, 10, 10, 100, 30, hwnd, (HMENU)1, NULL, NULL);
            state.hStopBtn = CreateWindow("BUTTON", "Parar", WS_CHILD | WS_VISIBLE, 120, 10, 100, 30, hwnd, (HMENU)2, NULL, NULL);
            state.hExportBtn = CreateWindow("BUTTON", "Exportar Relatório", WS_CHILD | WS_VISIBLE, 230, 10, 150, 30, hwnd, (HMENU)3, NULL, NULL);
            state.hText = CreateWindow("EDIT", "MalwareDetector rodando...\n", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                       10, 50, 460, 200, hwnd, NULL, NULL, NULL);
            state.hGraph = CreateWindow("STATIC", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 260, 460, 100, hwnd, NULL, NULL, NULL);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == 1) state.is_running = 1;
            if (LOWORD(wParam) == 2) state.is_running = 0;
            if (LOWORD(wParam) == 3) save_json_report();
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(state.hGraph, &ps);
            int cpu = check_cpu_usage();
            int height = (cpu * 100) / CPU_THRESHOLD;
            Rectangle(hdc, 10, 100 - height, 50, 100);
            EndPaint(state.hGraph, &ps);
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            state.is_running = 0;
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void init_gui() {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "MalwareDetectorWindow";
    RegisterClass(&wc);

    state.hwnd = CreateWindow("MalwareDetectorWindow", "MalwareDetector", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 500, 400, NULL, NULL, wc.hInstance, NULL);
    ShowWindow(state.hwnd, SW_SHOW);
}

#elif defined(__APPLE__)
// Função para detecção em memória (macOS)
void scan_memory() {
    int pids[1024];
    int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    count /= sizeof(int);

    for (int i = 0; i < count; i++) {
        task_t task;
        if (task_for_pid(mach_task_self(), pids[i], &task) == KERN_SUCCESS) {
            char buffer[1024];
            vm_size_t bytesRead;
            if (vm_read(task, 0x1000000, sizeof(buffer), (vm_offset_t *)&buffer, &bytesRead) == KERN_SUCCESS) {
                if (strstr(buffer, MEMORY_PATTERN)) {
                    state.total_memory_threats++;
                    char msg[512];
                    char proc_name[256];
                    proc_name_for_pid(pids[i], proc_name, sizeof(proc_name));
                    snprintf(msg, sizeof(msg), "Malware em memória detectado: %s (PID: %d)", proc_name, pids[i]);
                    log_message("ALERT", msg);
                }
            }
            mach_port_deallocate(mach_task_self(), task);
        }
    }
}

// Função para detectar rootkits (macOS)
void detect_rootkits() {
    int pids[1024];
    int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    count /= sizeof(int);

    for (int i = 0; i < count; i++) {
        char path[256];
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) {
            state.total_rootkits_detected++;
            char msg[512];
            snprintf(msg, sizeof(msg), "Rootkit potencial detectado: Processo oculto (PID: %d)", pids[i]);
            log_message("ALERT", msg);
        }
    }
}

// Função para escanear processos (macOS)
void scan_processes() {
    int pids[1024];
    int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    count /= sizeof(int);

    for (int i = 0; i < count; i++) {
        state.total_processes_scanned++;
        struct proc_bsdinfo proc;
        if (proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &proc, sizeof(proc)) > 0) {
            if (proc.pbi_utime + proc.pbi_stime > 1000000) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Processo suspeito detectado: %s (PID: %d)", proc.pbi_name, pids[i]);
                log_message("WARNING", msg);
            }
        }
    }
}

// Função para verificar alterações em arquivos críticos (macOS)
void check_critical_files() {
    struct stat st;
    const char *files[] = {"/etc/passwd", "/etc/sudoers", "/Library/Extensions", NULL};
    for (int i = 0; i < files[i]; i++) {
        if (stat(files[i], &st) == 0) {
            if (st.st_mtime > time(NULL) - 3600) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Alteração detectada em arquivo crítico: %s", files[i]);
                log_message("WARNING", msg);
            }
        }
    }
}

// Função para verificar conexões de rede (macOS)
void check_network_connections() {
    FILE *fp = popen("netstat -an | grep ESTABLISHED", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char remote_addr[64];
        int remote_port;
        if (sscanf(line, "%*s %*s %*s %*s %s", remote_addr) == 1) {
            char *port = strrchr(remote_addr, '.');
            if (port) {
                *port = '\0';
                remote_port = atoi(port + 1);
                char msg[512];
                snprintf(msg, sizeof(msg), "Conexão suspeita detectada: %s:%d", remote_addr, remote_port);
                log_message("WARNING", msg);
            }
        }
    }
    pclose(fp);
}

// Função para interface gráfica (macOS)
void init_gui() {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 500, 400)
                                                      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                        backing:NSBackingStoreBuffered
                                                          defer:NO];
        [window setTitle:@"MalwareDetector"];
        [window center];

        NSButton *startBtn = [[NSButton alloc] initWithFrame:NSMakeRect(10, 360, 100, 30)];
        [startBtn setTitle:@"Iniciar"];
        [startBtn setAction:@selector(startScanning:)];
        [startBtn setTarget:[NSApp delegate]];
        [[window contentView] addSubview:startBtn];

        NSButton *stopBtn = [[NSButton alloc] initWithFrame:NSMakeRect(120, 360, 100, 30)];
        [stopBtn setTitle:@"Parar"];
        [stopBtn setAction:@selector(stopScanning:)];
        [stopBtn setTarget:[NSApp delegate]];
        [[window contentView] addSubview:stopBtn];

        NSButton *exportBtn = [[NSButton alloc] initWithFrame:NSMakeRect(230, 360, 150, 30)];
        [exportBtn setTitle:@"Exportar Relatório"];
        [exportBtn setAction:@selector(exportReport:)];
        [exportBtn setTarget:[NSApp delegate]];
        [[window contentView] addSubview:exportBtn];

        NSTextView *textView = [[NSTextView alloc] initWithFrame:NSMakeRect(10, 50, 460, 300)];
        [textView setEditable:NO];
        [textView setString:@"MalwareDetector rodando...\n"];
        [[window contentView] addSubview:textView];

        state.window = window;
        state.startBtn = startBtn;
        state.stopBtn = stopBtn;
        state.exportBtn = exportBtn;
        state.textView = textView;

        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
    }
}

@interface AppDelegate : NSObject <NSApplicationDelegate>
@end
@implementation AppDelegate
- (void)startScanning:(id)sender { state.is_running = 1; }
- (void)stopScanning:(id)sender { state.is_running = 0; }
- (void)exportReport:(id)sender { save_json_report(); }
@end

#elif defined(__FreeBSD__)
// Função para detecção em memória (FreeBSD)
void scan_memory() {
    struct procstat *procstat = procstat_open_sysctl();
    if (!procstat) return;

    unsigned int count;
    struct kinfo_proc *procs = procstat_getprocs(procstat, KERN_PROC_ALL, 0, &count);
    if (!procs) {
        procstat_close(procstat);
        return;
    }

    for (unsigned int i = 0; i < count; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/map", procs[i].ki_pid);
        FILE *fp = fopen(path, "rb");
        if (fp) {
            char buffer[1024];
            size_t bytes = fread(buffer, 1, sizeof(buffer), fp);
            if (bytes > 0 && strstr(buffer, MEMORY_PATTERN)) {
                state.total_memory_threats++;
                char msg[512];
                snprintf(msg, sizeof(msg), "Malware em memória detectado: %s (PID: %d)", procs[i].ki_comm, procs[i].ki_pid);
                log_message("ALERT", msg);
            }
            fclose(fp);
        }
    }
    procstat_freeprocs(procstat, procs);
    procstat_close(procstat);
}

// Função para detectar rootkits (FreeBSD)
void detect_rootkits() {
    struct procstat *procstat = procstat_open_sysctl();
    if (!procstat) return;

    unsigned int count;
    struct kinfo_proc *procs = procstat_getprocs(procstat, KERN_PROC_ALL, 0, &count);
    if (!procs) {
        procstat_close(procstat);
        return;
    }

    for (unsigned int i = 0; i < count; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/file", procs[i].ki_pid);
        if (access(path, F_OK) != 0) {
            state.total_rootkits_detected++;
            char msg[512];
            snprintf(msg, sizeof(msg), "Rootkit potencial detectado: Processo oculto (PID: %d)", procs[i].ki_pid);
            log_message("ALERT", msg);
        }
    }
    procstat_freeprocs(procstat, procs);
    procstat_close(procstat);
}

// Função para escanear processos (FreeBSD)
void scan_processes() {
    struct procstat *procstat = procstat_open_sysctl();
    if (!procstat) {
        log_message("ERROR", "Falha ao obter lista de processos");
        return;
    }

    unsigned int count;
    struct kinfo_proc *procs = procstat_getprocs(procstat, KERN_PROC_ALL, 0, &count);
    if (!procs) {
        procstat_close(procstat);
        return;
    }

    for (unsigned int i = 0; i < count; i++) {
        state.total_processes_scanned++;
        if (procs[i].ki_uticks + procs[i].ki_sticks > 1000000) {
            char msg[512];
            snprintf(msg, sizeof(msg), "Processo suspeito detectado: %s (PID: %d)", procs[i].ki_comm, procs[i].ki_pid);
            log_message("WARNING", msg);
        }
    }
    procstat_freeprocs(procstat, procs);
    procstat_close(procstat);
}

// Função para verificar alterações em arquivos críticos (FreeBSD)
void check_critical_files() {
    struct stat st;
    const char *files[] = {"/etc/passwd", "/etc/master.passwd", "/boot/modules", NULL};
    for (int i = 0; files[i]; i++) {
        if (stat(files[i], &st) == 0) {
            if (st.st_mtime > time(NULL) - 3600) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Alteração detectada em arquivo crítico: %s", files[i]);
                log_message("WARNING", msg);
            }
        }
    }
}

// Função para verificar conexões de rede (FreeBSD)
void check_network_connections() {
    FILE *fp = popen("netstat -an | grep ESTABLISHED", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char remote_addr[64];
        int remote_port;
        if (sscanf(line, "%*s %*s %*s %*s %s", remote_addr) == 1) {
            char *port = strrchr(remote_addr, '.');
            if (port) {
                *port = '\0';
                remote_port = atoi(port + 1);
                char msg[512];
                snprintf(msg, sizeof(msg), "Conexão suspeita detectada: %s:%d", remote_addr, remote_port);
                log_message("WARNING", msg);
            }
        }
    }
    pclose(fp);
}

// Função para interface gráfica (FreeBSD/Linux)
void on_start_clicked(GtkButton *button, gpointer data) { state.is_running = 1; }
void on_stop_clicked(GtkButton *button, gpointer data) { state.is_running = 0; }
void on_export_clicked(GtkButton *button, gpointer data) { save_json_report(); }
gboolean on_draw_graph(GtkWidget *widget, cairo_t *cr, gpointer data) {
    int cpu = check_cpu_usage();
    double height = (cpu * 100.0) / CPU_THRESHOLD;
    cairo_set_source_rgb(cr, 0, 0, 1);
    cairo_rectangle(cr, 10, 100 - height, 40, height);
    cairo_fill(cr);
    return FALSE;
}
void on_window_destroy(GtkWidget *widget, gpointer data) {
    state.is_running = 0;
    gtk_main_quit();
}

void init_gui() {
    gtk_init(NULL, NULL);
    state.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(state.window), "MalwareDetector");
    gtk_window_set_default_size(GTK_WINDOW(state.window), 500, 400);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(state.window), vbox);

    state.start_btn = gtk_button_new_with_label("Iniciar");
    gtk_box_pack_start(GTK_BOX(vbox), state.start_btn, FALSE, FALSE, 5);
    g_signal_connect(state.start_btn, "clicked", G_CALLBACK(on_start_clicked), NULL);

    state.stop_btn = gtk_button_new_with_label("Parar");
    gtk_box_pack_start(GTK_BOX(vbox), state.stop_btn, FALSE, FALSE, 5);
    g_signal_connect(state.stop_btn, "clicked", G_CALLBACK(on_stop_clicked), NULL);

    state.export_btn = gtk_button_new_with_label("Exportar Relatório");
    gtk_box_pack_start(GTK_BOX(vbox), state.export_btn, FALSE, FALSE, 5);
    g_signal_connect(state.export_btn, "clicked", G_CALLBACK(on_export_clicked), NULL);

    state.text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(state.text_view), FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), state.text_view, TRUE, TRUE, 5);
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(state.text_view));
    gtk_text_buffer_set_text(buffer, "MalwareDetector rodando...\n", -1);

    state.graph_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(state.graph_area, 460, 100);
    gtk_box_pack_start(GTK_BOX(vbox), state.graph_area, FALSE, FALSE, 5);
    g_signal_connect(state.graph_area, "draw", G_CALLBACK(on_draw_graph), NULL);

    g_signal_connect(state.window, "destroy", G_CALLBACK(on_window_destroy), NULL);
    gtk_widget_show_all(state.window);
}

#else
// Função para detecção em memória (Linux)
void scan_memory() {
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/mem", pid);
        FILE *fp = fopen(path, "rb");
        if (fp) {
            char buffer[1024];
            size_t bytes = fread(buffer, 1, sizeof(buffer), fp);
            if (bytes > 0 && strstr(buffer, MEMORY_PATTERN)) {
                state.total_memory_threats++;
                char msg[512];
                snprintf(msg, sizeof(msg), "Malware em memória detectado: PID %d", pid);
                log_message("ALERT", msg);
            }
            fclose(fp);
        }
    }
    closedir(dir);
}

// Função para detectar rootkits (Linux)
void detect_rootkits() {
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *fp = fopen(path, "r");
        if (!fp) {
            state.total_rootkits_detected++;
            char msg[512];
            snprintf(msg, sizeof(msg), "Rootkit potencial detectado: Processo oculto (PID: %d)", pid);
            log_message("ALERT", msg);
        } else {
            fclose(fp);
        }
    }
    closedir(dir);
}

// Função para escanear processos (Linux)
void scan_processes() {
    DIR *dir = opendir("/proc");
    if (!dir) {
        log_message("ERROR", "Falha ao abrir /proc");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        state.total_processes_scanned++;
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *fp = fopen(path, "r");
        if (fp) {
            long utime, stime;
            char comm[256];
            fscanf(fp, "%*d %s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld", comm, &utime, &stime);
            fclose(fp);
            if (utime + stime > 1000000) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Processo suspeito detectado: %s (PID: %d)", comm, pid);
                log_message("WARNING", msg);
            }
        }
    }
    closedir(dir);
}

// Função para verificar alterações em arquivos críticos (Linux)
void check_critical_files() {
    struct stat st;
    const char *files[] = {"/etc/passwd", "/etc/shadow", "/lib/modules", NULL};
    for (int i = 0; i < files[i]; i++) {
        if (stat(files[i], &st) == 0) {
            if (st.st_mtime > time(NULL) - 3600) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Alteração detectada em arquivo crítico: %s", files[i]);
                log_message("WARNING", msg);
            }
        }
    }
}

// Função para verificar conexões de rede (Linux)
void check_network_connections() {
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) return;

    char line[256];
    fgets(line, sizeof(line), fp); // Ignorar cabeçalho
    while (fgets(line, sizeof(line), fp)) {
        unsigned int local_addr, remote_addr;
        int local_port, remote_port;
        sscanf(line, "%*d: %x:%x %x:%x", &local_addr, &local_port, &remote_addr, &remote_port);
        if (remote_addr != 0) {
            char remote_ip[16];
            snprintf(remote_ip, sizeof(remote_ip), "%d.%d.%d.%d",
                     (remote_addr & 0xFF), (remote_addr >> 8) & 0xFF,
                     (remote_addr >> 16) & 0xFF, (remote_addr >> 24) & 0xFF);
            char msg[512];
            snprintf(msg, sizeof(msg), "Conexão suspeita detectada: %s:%d", remote_ip, remote_port);
            log_message("WARNING", msg);
        }
    }
    fclose(fp);
}

// Função para interface gráfica (Linux)
void on_start_clicked(GtkButton *button, gpointer data) { state.is_running = 1; }
void on_stop_clicked(GtkButton *button, gpointer data) { state.is_running = 0; }
void on_export_clicked(GtkButton *button, gpointer data) { save_json_report(); }
gboolean on_draw_graph(GtkWidget *widget, cairo_t *cr, gpointer data) {
    int cpu = check_cpu_usage();
    double height = (cpu * 100.0) / CPU_THRESHOLD;
    cairo_set_source_rgb(cr, 0, 0, 1);
    cairo_rectangle(cr, 10, 100 - height, 40, height);
    cairo_fill(cr);
    return FALSE;
}
void on_window_destroy(GtkWidget *widget, gpointer data) {
    state.is_running = 0;
    gtk_main_quit();
}

void init_gui() {
    gtk_init(NULL, NULL);
    state.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(state.window), "MalwareDetector");
    gtk_window_set_default_size(GTK_WINDOW(state.window), 500, 400);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(state.window), vbox);

    state.start_btn = gtk_button_new_with_label("Iniciar");
    gtk_box_pack_start(GTK_BOX(vbox), state.start_btn, FALSE, FALSE, 5);
    g_signal_connect(state.start_btn, "clicked", G_CALLBACK(on_start_clicked), NULL);

    state.stop_btn = gtk_button_new_with_label("Parar");
    gtk_box_pack_start(GTK_BOX(vbox), state.stop_btn, FALSE, FALSE, 5);
    g_signal_connect(state.stop_btn, "clicked", G_CALLBACK(on_stop_clicked), NULL);

    state.export_btn = gtk_button_new_with_label("Exportar Relatório");
    gtk_box_pack_start(GTK_BOX(vbox), state.export_btn, FALSE, FALSE, 5);
    g_signal_connect(state.export_btn, "clicked", G_CALLBACK(on_export_clicked), NULL);

    state.text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(state.text_view), FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), state.text_view, TRUE, TRUE, 5);
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(state.text_view));
    gtk_text_buffer_set_text(buffer, "MalwareDetector rodando...\n", -1);

    state.graph_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(state.graph_area, 460, 100);
    gtk_box_pack_start(GTK_BOX(vbox), state.graph_area, FALSE, FALSE, 5);
    g_signal_connect(state.graph_area, "draw", G_CALLBACK(on_draw_graph), NULL);

    g_signal_connect(state.window, "destroy", G_CALLBACK(on_window_destroy), NULL);
    gtk_widget_show_all(state.window);
}
#endif

// Função para escanear arquivos
void scan_files(const char *dir_path) {
    unsigned char *file_buffer = NULL;
    size_t file_size = 0;

    #ifdef _WIN32
    WIN32_FIND_DATA ffd;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*.*", dir_path);
    HANDLE hFind = FindFirstFile(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        log_message("ERROR", "Falha ao escanear diretório");
        return;
    }

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(ffd.cFileName, ".") != 0 && strcmp(ffd.cFileName, "..") != 0) {
                char sub_dir[MAX_PATH];
                snprintf(sub_dir, sizeof(sub_dir), "%s\\%s", dir_path, ffd.cFileName);
                scan_files(sub_dir);
            }
        } else {
            char file_path[MAX_PATH];
            snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, ffd.cFileName);
            FILE *file = fopen(file_path, "rb");
            if (file) {
                fseek(file, 0, SEEK_END);
                file_size = ftell(file);
                fseek(file, 0, SEEK_SET);
                file_buffer = malloc(file_size);
                if (file_buffer) {
                    fread(file_buffer, 1, file_size, file);
                }
                fclose(file);
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            calculate_sha256(file_path, hash);
            char hash_str[65];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                sprintf(&hash_str[i * 2], "%02x", hash[i]);
            }
            hash_str[64] = 0;
            state.total_files_scanned++;

            int is_malware = 0;
            if (check_signature(hash_str) || check_yara(file_path)) {
                is_malware = 1;
            } else if (file_buffer && file_size > 0) {
                double entropy = calculate_entropy(file_buffer, file_size);
                if (entropy > ENTROPY_THRESHOLD) {
                    state.total_polymorphic_detected++;
                    is_malware = 1;
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Malware polimórfico detectado: %s (Entropia: %.2f)", file_path, entropy);
                    log_message("ALERT", msg);
                }
            }
            if (is_malware) {
                state.total_malwares_detected++;
                char msg[512];
                snprintf(msg, sizeof(msg), "Malware detectado: %s (SHA-256: %s)", file_path, hash_str);
                log_message("ALERT", msg);
            }
            free(file_buffer);
            file_buffer = NULL;
        }
    } while (FindNextFile(hFind, &ffd));
    FindClose(hFind);
    #else
    DIR *dir = opendir(dir_path);
    if (!dir) {
        log_message("ERROR", "Falha ao abrir diretório");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char sub_dir[256];
                snprintf(sub_dir, sizeof(sub_dir), "%s/%s", dir_path, entry->d_name);
                scan_files(sub_dir);
            }
        } else if (entry->d_type == DT_REG) {
            char file_path[256];
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
            FILE *file = fopen(file_path, "rb");
            if (file) {
                fseek(file, 0, SEEK_END);
                file_size = ftell(file);
                fseek(file, 0, SEEK_SET);
                file_buffer = malloc(file_size);
                if (file_buffer) {
                    fread(file_buffer, 1, file_size, file);
                }
                fclose(file);
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            calculate_sha256(file_path, hash);
            char hash_str[65];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                sprintf(&hash_str[i * 2], "%02x", hash[i]);
            }
            hash_str[64] = 0;
            state.total_files_scanned++;

            int is_malware = 0;
            if (check_signature(hash_str) || check_yara(file_path)) {
                is_malware = 1;
            } else if (file_buffer && file_size > 0) {
                double entropy = calculate_entropy(file_buffer, file_size);
                if (entropy > ENTROPY_THRESHOLD) {
                    state.total_polymorphic_detected++;
                    is_malware = 1;
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Malware polimórfico detectado: %s (Entropia: %.2f)", file_path, entropy);
                    log_message("ALERT", msg);
                }
            }
            if (is_malware) {
                state.total_malwares_detected++;
                char msg[512];
                snprintf(msg, sizeof(msg), "Malware detectado: %s (SHA-256: %s)", file_path, hash_str);
                log_message("ALERT", msg);
            }
            free(file_buffer);
            file_buffer = NULL;
        }
    }
    closedir(dir);
    #endif
}

// Função para escaneamento completo
void *scan_thread(void *arg) {
    while (state.is_running) {
        if (check_cpu_usage() > CPU_THRESHOLD) {
            log_message("WARNING", "Uso de CPU alto, pausando escaneamento por 1s");
            #ifdef _WIN32
            Sleep(1000);
            #else
            sleep(1);
            #endif
            continue;
        }

        scan_files(SCAN_DIR);
        scan_processes();
        scan_memory();
        detect_rootkits();
        #ifdef _WIN32
        check_registry_changes();
        check_network_connections();
        InvalidateRect(state.hGraph, NULL, TRUE);
        Sleep(SCAN_INTERVAL * 1000);
        #elif defined(__APPLE__)
        check_critical_files();
        check_network_connections();
        sleep(SCAN_INTERVAL);
        #elif defined(__FreeBSD__)
        check_critical_files();
        check_network_connections();
        gtk_widget_queue_draw(state.graph_area);
        sleep(SCAN_INTERVAL);
        #else
        check_critical_files();
        check_network_connections();
        gtk_widget_queue_draw(state.graph_area);
        sleep(SCAN_INTERVAL);
        #endif
    }
    return NULL;
}

// Função para rodar GUI
#ifdef _WIN32
void *gui_thread(void *arg) {
    init_gui();
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return NULL;
}
#elif defined(__APPLE__)
void *gui_thread(void *arg) {
    init_gui();
    [NSApp run];
    return NULL;
}
#else
void *gui_thread(void *arg) {
    init_gui();
    gtk_main();
    return NULL;
}
#endif

// Função principal
int main(int argc, char *argv[]) {
    // Criar diretórios
    #ifdef _WIN32
    CreateDirectory("logs", NULL);
    CreateDirectory(REPORT_DIR, NULL);
    #else
    mkdir("logs", 0777);
    mkdir(REPORT_DIR, 0777);
    #endif

    // Inicializar JSON
    init_json_report();

    log_message("INFO", "MalwareDetector iniciado");
    state.is_running = 1;

    // Criar arquivo de assinaturas e regras YARA (exemplo)
    FILE *sig_file = fopen(SIGNATURES_FILE, "w");
    if (sig_file) {
        fprintf(sig_file, "d41d8cd98f00b204e9800998ecf8427e\n");
        fclose(sig_file);
    }
    FILE *yara_file = fopen(YARA_RULES, "w");
    if (yara_file) {
        fprintf(yara_file, "rule TestRule { strings: $a = \"malware\" condition: $a }\n");
        fclose(yara_file);
    }

    // Iniciar threads
    pthread_t scan_thread_id, gui_thread_id;
    pthread_create(&scan_thread_id, NULL, scan_thread, NULL);
    pthread_create(&gui_thread_id, NULL, gui_thread, NULL);

    // Aguardar threads
    pthread_join(scan_thread_id, NULL);
    pthread_join(gui_thread_id, NULL);

    save_json_report();
    json_object_put(state.report_json);

    log_message("INFO", "MalwareDetector finalizado");
    return 0;
}