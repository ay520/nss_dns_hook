// 启用 GNU 扩展特性
#define _GNU_SOURCE

// 包含必要的头文件
#include <stddef.h>  
#include <stdlib.h>  
#include <nss.h>       
#include <netdb.h>     
#include <arpa/inet.h> 
#include <unistd.h>    
#include <string.h>    
#include <stdio.h>     
#include <errno.h>     
#include <sys/types.h>     
#include <sys/socket.h>    
#include <netinet/in.h>    
#include <stdbool.h>      
#include <resolv.h>      
#include "dns_log.h"
#include "get_cmdchain.c"
#include "uthash.h"

// 常量定义
#define MAX_DOMAIN_LENGTH 256  
#define MAX_ADDRESSES 16       
#define DEFAULT_TTL 300       
#define ALIGN(x) (((x) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))
#define WHITELIST_FILE "/etc/nss_whitelist.conf"
#define MAX_WHITELIST_ENTRIES 10000

// 在文件开头添加新的定义
#define CUSTOM_NETWORKS_FILE "/etc/nss_private_networks.conf"
#define MAX_CUSTOM_NETWORKS 100


// 定义网络结构
struct ipv4_network {
    uint32_t network;    // 网络地址
    uint32_t mask;       // 子网掩码
};

struct ipv6_network {
    uint8_t network[16];  // 网络地址
    uint8_t mask[16];     // 子网掩码
    int prefix_len;       // 前缀长度
};

// 网络类型枚举
enum network_type {
    TYPE_IPV4,
    TYPE_IPV6
};

// 统一的网络结构
struct network_entry {
    enum network_type type;
    union {
        struct ipv4_network ipv4;
        struct ipv6_network ipv6;
    };
};

// 全局变量存储自定义网络
static struct network_entry custom_networks[MAX_CUSTOM_NETWORKS];
static int custom_networks_count = 0;


// 缓冲区数据结构
struct buffer_data {
    char *buffer;      
    size_t buflen;     
    size_t offset;     
};

// 生成 IPv6 子网掩码
static void generate_ipv6_mask(uint8_t *mask, int prefix_len) {
    memset(mask, 0, 16);
    int full_bytes = prefix_len / 8;
    int remaining_bits = prefix_len % 8;
    
    // 设置完整的字节
    memset(mask, 0xFF, full_bytes);
    
    // 设置剩余的位
    if (remaining_bits > 0 && full_bytes < 16) {
        mask[full_bytes] = (0xFF << (8 - remaining_bits)) & 0xFF;
    }
}

// 解析CIDR格式的网段
static bool parse_cidr(const char *cidr, struct network_entry *entry) {
    char ip_str[46];  // 足够存储 IPv6 地址
    int prefix_len;
    
    if (sscanf(cidr, "%45[^/]/%d", ip_str, &prefix_len) != 2) {
        return false;
    }
    
    // 尝试解析为 IPv4
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        if (prefix_len < 0 || prefix_len > 32) {
            return false;
        }
        
        entry->type = TYPE_IPV4;
        entry->ipv4.network = ntohl(addr4.s_addr);
        entry->ipv4.mask = prefix_len == 0 ? 0 : (0xffffffff << (32 - prefix_len));
        return true;
    }
    
    // 尝试解析为 IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        if (prefix_len < 0 || prefix_len > 128) {
            return false;
        }
        
        entry->type = TYPE_IPV6;
        memcpy(entry->ipv6.network, addr6.s6_addr, 16);
        generate_ipv6_mask(entry->ipv6.mask, prefix_len);
        entry->ipv6.prefix_len = prefix_len;
        return true;
    }
    
    return false;
}

// 加载自定义网络配置
static void load_custom_networks(void) {
    FILE *fp = fopen(CUSTOM_NETWORKS_FILE, "r");
    if (!fp) {
        dns_log(LOG_WARNING, "Could not open custom networks file: %s", CUSTOM_NETWORKS_FILE);
        return;
    }

    char line[64];
    while (fgets(line, sizeof(line), fp) && custom_networks_count < MAX_CUSTOM_NETWORKS) {
        // 移除换行符
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        // 跳过空行和注释
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        if (parse_cidr(line, &custom_networks[custom_networks_count])) {
            dns_log(LOG_INFO, "Added custom private network: %s", line);
            custom_networks_count++;
        } else {
            dns_log(LOG_WARNING, "Invalid network format: %s", line);
        }
    }

    fclose(fp);
    dns_log(LOG_INFO, "Loaded %d custom private networks", custom_networks_count);
}

// 检查 IPv6 地址是否在网段内
static bool ipv6_in_network(const uint8_t *addr, const struct ipv6_network *network) {
    for (int i = 0; i < 16; i++) {
        if ((addr[i] & network->mask[i]) != (network->network[i] & network->mask[i])) {
            return false;
        }
    }
    return true;
}

// 修改 is_private_ip 函数
static bool is_private_ip(const unsigned char *addr, int family) {
    if (family == AF_INET) {
        uint32_t ip = *(uint32_t*)addr;
        ip = ntohl(ip);
        
        // 标准私有网络检查
        // 10.0.0.0/8
        if ((ip >> 24) == 10) return true;
        
        // 172.16.0.0/12
        uint8_t second_octet = (ip >> 16) & 0xFF;
        if ((ip >> 24) == 172 && (second_octet >= 16 && second_octet <= 31)) return true;
        
        // 192.168.0.0/16
        if ((ip >> 16) == (192 << 8 | 168)) return true;
        
        // 127.0.0.0/8
        if ((ip >> 24) == 127) return true;

        // 169.254.0.0/16
        if ((ip >> 16) == (169 << 8 | 254)) return true;
        
        // 检查自定义网络
        for (int i = 0; i < custom_networks_count; i++) {
            if (custom_networks[i].type == TYPE_IPV4) {
                if ((ip & custom_networks[i].ipv4.mask) == 
                    (custom_networks[i].ipv4.network & custom_networks[i].ipv4.mask)) {
                    return true;
                }
            }
        }
        
        return false;
    } 
    else if (family == AF_INET6) {
        const uint8_t *addr_bytes = addr;
        
        // 标准私有网络检查
        // fe80::/10 (Link-local)
        if (addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80) return true;
        
        // fc00::/7 (Unique local)
        if ((addr_bytes[0] & 0xfe) == 0xfc) return true;
        
        // ::1/128 (Loopback)
        bool is_loopback = true;
        for (int i = 0; i < 15; i++) {
            if (addr_bytes[i] != 0) {
                is_loopback = false;
                break;
            }
        }
        if (is_loopback && addr_bytes[15] == 1) return true;
        
        // 检查自定义网络
        for (int i = 0; i < custom_networks_count; i++) {
            if (custom_networks[i].type == TYPE_IPV6) {
                if (ipv6_in_network(addr_bytes, &custom_networks[i].ipv6)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    return false;
}


struct whitelist_entry {
    char *domain;            
    int is_wildcard;        
    char *suffix;           
    UT_hash_handle hh;      
};

static struct whitelist_entry *whitelist_hash = NULL;

static int load_whitelist(void) {
    FILE *fp = fopen(WHITELIST_FILE, "r");
    if (!fp) {
        dns_log(LOG_WARNING, "Could not open whitelist file: %s", WHITELIST_FILE);
        return 0;
    }

    char line[MAX_DOMAIN_LENGTH];
    struct whitelist_entry *entry;
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        entry = (struct whitelist_entry*)malloc(sizeof(struct whitelist_entry));
        if (!entry) continue;

        entry->domain = strdup(line);
        if (!entry->domain) {
            free(entry);
            continue;
        }

        entry->is_wildcard = (entry->domain[0] == '*');
        if (entry->is_wildcard) {
            entry->suffix = entry->domain + 1;
        } else {
            entry->suffix = NULL;
        }

        // 使用 HASH_ADD_STR 替代 HASH_ADD_KEYPTR
        HASH_ADD_STR(whitelist_hash, domain, entry);
        count++;
        if(count> MAX_WHITELIST_ENTRIES) 
        {
            dns_log(LOG_WARNING,"config file lines more than MAX_WHITELIST_ENTRIES sets");
            break;
        }
    }

    fclose(fp);
    dns_log(LOG_INFO, "Loaded %d domains into whitelist", count);
    return count;
}

static int is_domain_whitelisted(const char *domain) {
    if (!domain) return 0;

    struct whitelist_entry *entry;
    
    // 使用 HASH_FIND_STR 查找
    HASH_FIND_STR(whitelist_hash, domain, entry);
    if (entry) return 1;

    // 查找通配符匹配
    const char *dot = strchr(domain, '.');
    if (dot) {
        // 构建通配符形式的域名
        char wildcard_domain[MAX_DOMAIN_LENGTH];
        snprintf(wildcard_domain, sizeof(wildcard_domain), "*%s", dot);
        
        // 在哈希表中查找通配符域名
        HASH_FIND_STR(whitelist_hash, wildcard_domain, entry);
        if (entry) return 1;
    }


    return 0;
}

static void cleanup_whitelist(void) {
    struct whitelist_entry *current, *tmp;
    
    if (whitelist_hash == NULL) {
        return;
    }
    
    HASH_ITER(hh, whitelist_hash, current, tmp) {
        if (current) {
            HASH_DEL(whitelist_hash, current);
            if (current->domain) {
                free(current->domain);
            }
            free(current);
        }
    }
    whitelist_hash = NULL;  // 清理后设置为 NULL
}


// 添加一个辅助函数来打印单个地址
static void print_address(const struct gaih_addrtuple *addr) {
    char ip_str[INET6_ADDRSTRLEN];
    
    if (addr->family == AF_INET) {
        // IPv4 地址
        if (inet_ntop(AF_INET, addr->addr, ip_str, sizeof(ip_str))) {
            dns_log(LOG_INFO, "IPv4: %s", ip_str);
        }
    } 
    else if (addr->family == AF_INET6) {
        // IPv6 地址
        if (inet_ntop(AF_INET6, addr->addr, ip_str, sizeof(ip_str))) {
            dns_log(LOG_INFO, "IPv6: %s", ip_str);
        }
    }
}

// 添加一个函数来打印整个地址链表
static void print_address_list(const struct gaih_addrtuple *pat) {
    dns_log(LOG_INFO, "Address list content:");
    const struct gaih_addrtuple *current = pat;
    int count = 0;
    
    while (current != NULL) {
        dns_log(LOG_INFO, "Address #%d:", ++count);
        print_address(current);
        current = current->next;
    }
    
    dns_log(LOG_INFO, "Total addresses: %d", count);
}

// 安全的内存分配函数
static void* safe_allocate(struct buffer_data *buf, size_t size) {
    if (!buf || !buf->buffer || size == 0) {
        return NULL;
    }
    
    size_t aligned_size = ALIGN(size);
    if (buf->offset + aligned_size > buf->buflen) {
        return NULL;
    }
    
    void *ptr = buf->buffer + buf->offset;
    buf->offset += aligned_size;
    memset(ptr, 0, aligned_size);
    return ptr;
}

// 添加IPv4地址到结果链表
static bool add_ipv4_address(struct buffer_data *buf,
                           struct gaih_addrtuple **pat,
                           struct gaih_addrtuple **prev,
                           const unsigned char *addr_data,
                           int *addr_count,
                           const char *domain) 
{
    // 检查是否为内网IP
    bool is_private = is_private_ip(addr_data, AF_INET);
    
    // 如果是公网IP且域名不在白名单中，返回127.0.0.1
    unsigned char localhost[4] = {127, 0, 0, 1};
    const unsigned char *final_addr = addr_data;
    
    if (!is_private && !is_domain_whitelisted(domain)) {
        final_addr = localhost;
        char ip_str[48];
        inet_ntop(AF_INET, addr_data, ip_str, sizeof(ip_str));
        dns_log(LOG_INFO, "Redirecting domain:%s addr:%s to localhost (IPv4)", domain,ip_str);
    }

    struct gaih_addrtuple *current = safe_allocate(buf, sizeof(struct gaih_addrtuple));
    if (!current) {
        return false;
    }

    current->next = NULL;
    current->name = NULL;
    current->family = AF_INET;
    memcpy(&current->addr[0], final_addr, NS_INADDRSZ);
    current->scopeid = 0;

    if (*prev) {
        (*prev)->next = current;
    } else {
        *pat = current;
    }
    
    *prev = current;
    (*addr_count)++;
    return true;
}

// 添加IPv6地址到结果链表
static bool add_ipv6_address(struct buffer_data *buf,
                           struct gaih_addrtuple **pat,
                           struct gaih_addrtuple **prev,
                           const unsigned char *addr_data,
                           int *addr_count,
                           const char *domain) 
{
    // 检查是否为内网IP
    bool is_private = is_private_ip(addr_data, AF_INET6);
    
    // 如果是公网IP且域名不在白名单中，返回::1
    unsigned char localhost[16] = {0};
    localhost[15] = 1;  // ::1
    const unsigned char *final_addr = addr_data;
    
    if (!is_private && !is_domain_whitelisted(domain)) {
        final_addr = localhost;
        char ip_str[48];
        inet_ntop(AF_INET6, addr_data, ip_str, sizeof(ip_str));
        dns_log(LOG_INFO, "Redirecting domain:%s addr:%s to localhost (IPv6)", domain,ip_str);
    }

    struct gaih_addrtuple *current = safe_allocate(buf, sizeof(struct gaih_addrtuple));
    if (!current) {
        return false;
    }

    current->next = NULL;
    current->name = NULL;
    current->family = AF_INET6;
    memcpy(&current->addr[0], final_addr, NS_IN6ADDRSZ);
    current->scopeid = 0;

    if (*prev) {
        (*prev)->next = current;
    } else {
        *pat = current;
    }
    
    *prev = current;
    (*addr_count)++;
    return true;
}

// NSS 模块的主要函数
enum nss_status _nss_hs_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop,
    int32_t *ttlp)
{
    // 参数检查
    if (!name || !pat || !buffer || !errnop || !h_errnop || 
        buflen < sizeof(struct gaih_addrtuple)) {
        if (errnop) *errnop = EINVAL;
        if (h_errnop) *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }


    char *cmdline=read_cmdline(getpid());
    char *exe_path=read_proc_path(getpid());
    dns_log(LOG_INFO, "ns(4) hook domain: %s pid: %d,program:%s,proc_path:%s", name, getpid(),cmdline,exe_path); // 记录日志信息，包括域名和进程ID
    free(cmdline);
    free(exe_path);


    // 检查域名长度
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= MAX_DOMAIN_LENGTH) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
    if(!load_whitelist()){

        return NSS_STATUS_NOTFOUND;
    }
    

    // 初始化resolver
    struct __res_state res;
    if (res_ninit(&res) != 0) {
        *errnop = EAGAIN;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    struct buffer_data buf = {
        .buffer = buffer,
        .buflen = buflen,
        .offset = 0
    };

    unsigned char answer[NS_MAXMSG];
    int addr_count = 0;
    struct gaih_addrtuple *prev = NULL;

    // 查询A记录（IPv4）
    int len = res_nquery(&res, name, C_IN, T_A, answer, sizeof(answer));
    if (len > 0) {
        ns_msg handle;
        ns_rr rr;
        
        if (ns_initparse(answer, len, &handle) >= 0) {
            int count = ns_msg_count(handle, ns_s_an);
            for (int i = 0; i < count && addr_count < MAX_ADDRESSES; i++) {
                if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
                    continue;
                }

                if (ns_rr_type(rr) == ns_t_a) {
                    if (!add_ipv4_address(&buf, pat, &prev, ns_rr_rdata(rr), &addr_count, name)) {
                        res_nclose(&res);
                        *errnop = ERANGE;
                        *h_errnop = NO_RECOVERY;
                        return NSS_STATUS_TRYAGAIN;
                    }
                }
            }
        }
    }

    // 查询AAAA记录（IPv6）
    len = res_nquery(&res, name, C_IN, T_AAAA, answer, sizeof(answer));
    if (len > 0) {
        ns_msg handle;
        ns_rr rr;
        
        if (ns_initparse(answer, len, &handle) >= 0) {
            int count = ns_msg_count(handle, ns_s_an);
            for (int i = 0; i < count && addr_count < MAX_ADDRESSES; i++) {
                if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
                    continue;
                }

                if (ns_rr_type(rr) == ns_t_aaaa) {
                    if (!add_ipv6_address(&buf, pat, &prev, ns_rr_rdata(rr), &addr_count, name)) {
                        res_nclose(&res);
                        *errnop = ERANGE;
                        *h_errnop = NO_RECOVERY;
                        return NSS_STATUS_TRYAGAIN;
                    }
                }
            }
        }
    }

    // 清理resolver
    res_nclose(&res);
    
    // 安全清理白名单
    if (whitelist_hash != NULL) {
        cleanup_whitelist();
    }

    // 检查是否找到地址
    if (addr_count == 0) {
        dns_log(LOG_INFO, "No addresses found for %s", name);
       
        // // 设置错误状态
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        
    
        return NSS_STATUS_NOTFOUND;

    }

    // 在返回 SUCCESS 之前添加打印
    if (addr_count > 0) {
        dns_log(LOG_INFO, "Final address list for %s:", name);
        print_address_list(*pat);
    }

    // 设置TTL
    if (ttlp) {
        *ttlp = DEFAULT_TTL;
    }

    dns_log(LOG_INFO, "Successfully resolved %s with %d addresses", name, addr_count);
    return NSS_STATUS_SUCCESS;
}



// _nss_hs_gethostbyname3_r函数提供了对特定的IPv4和IPv6协议族的支持
enum nss_status _nss_hs_gethostbyname3_r(
    const char *name,        // 要解析的主机名
    int af,                  // 地址协议族，用于指定解析类型（IPv4、IPv6等）
    struct hostent *result,    // 结果存储在此结构中
    char *buffer,            // 用于存储地址的缓冲区
    size_t buflen,           // 缓冲区的长度
    int *errnop,             // 存储错误代码的指针
    int *h_errnop,           // 存储主机错误代码的指针
    int32_t *ttlp,           // 用于存储TTL值的可选指针
    char **canonp            // 返回主机名的规范名称的可选指针
) {


        // 参数验证
    if (!name || !result || !buffer || !errnop || !h_errnop) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    char *cmdline=read_cmdline(getpid());
    char *exe_path=read_proc_path(getpid());
    dns_log(LOG_INFO, "ns(3) hook domain: %s pid: %d,program:%s,proc_path:%s", name, getpid(),cmdline,exe_path); // 记录日志信息，包括域名和进程ID
    free(cmdline);
    free(exe_path);

    // 分配临时缓冲区用于 gethostbyname4_r
    char *tmp_buffer = malloc(buflen);
    if (!tmp_buffer) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    struct gaih_addrtuple *pat = NULL;
    enum nss_status status = _nss_hs_gethostbyname4_r(name, &pat, tmp_buffer, buflen, errnop, h_errnop, ttlp);

    if (status != NSS_STATUS_SUCCESS) {
        free(tmp_buffer);
        return status;
    }

    // 转换结果格式
    result->h_name = name;
    result->h_aliases = NULL;
    result->h_addrtype = af;
    result->h_length = (af == AF_INET) ? 4 : 16;

    // 计算符合请求地址族的地址数量
    int addr_count = 0;
    struct gaih_addrtuple *current = pat;
    while (current) {
        if (current->family == af) addr_count++;
        current = current->next;
    }

    if (addr_count == 0) {
        free(tmp_buffer);
        *errnop = ENOENT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    }

    // 准备地址列表
    char **addr_list = (char **)buffer;
    char *addr_ptr = buffer + (addr_count + 1) * sizeof(char *);
    
    // 检查缓冲区大小
    if (buflen < (addr_count + 1) * sizeof(char *) + addr_count * result->h_length) {
        free(tmp_buffer);
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    result->h_addr_list = addr_list;

    // 复制地址
    current = pat;
    int i = 0;
    while (current && i < addr_count) {
        if (current->family == af) {
            addr_list[i] = addr_ptr;
            memcpy(addr_ptr, current->addr, result->h_length);
            addr_ptr += result->h_length;
            i++;
        }
        current = current->next;
    }
    addr_list[i] = NULL;

    if (canonp) *canonp = NULL;

    free(tmp_buffer);
    return NSS_STATUS_SUCCESS;

}

// _nss_hs_gethostbyname2_r函数用于支持较旧的接口，并返回基本的地址信息
enum nss_status _nss_hs_gethostbyname2_r(
    const char *name,        // 要解析的主机名
    int af,                  // 地址协议族
    struct hostent *result,    // 用于存储解析结果的结构
    char *buffer,            // 缓冲区
    size_t buflen,           // 缓冲区大小
    int *errnop,             // 错误码指针
    int *h_errnop            // 主机错误码指针
) {
    
    
    char *cmdline=read_cmdline(getpid());
    char *exe_path=read_proc_path(getpid());
    dns_log(LOG_INFO, "ns(2) hook domain: %s pid: %d,program:%s,proc_path:%s", name, getpid(),cmdline,exe_path); // 记录日志信息，包括域名和进程ID
    free(cmdline);
    free(exe_path);

    return _nss_hs_gethostbyname3_r(name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);


}

// _nss_hs_gethostbyname_r函数实际上是最原始的接口，用于解析任意主机名，默认支持IPv4
enum nss_status _nss_hs_gethostbyname_r(
    const char *name,        // 要解析的主机名
    struct hostent *result,    // 用于存储解析结果的结构
    char *buffer,            // 缓冲区
    size_t buflen,           // 缓冲区大小
    int *errnop,             // 错误码指针
    int *h_errnop            // 主机错误码指针
) {


    char *cmdline=read_cmdline(getpid());
    char *exe_path=read_proc_path(getpid());
    dns_log(LOG_INFO, "ns hook domain: %s pid: %d,program:%s,proc_path:%s", name, getpid(),cmdline,exe_path); // 记录日志信息，包括域名和进程ID
    free(cmdline);
    free(exe_path);

    return _nss_hs_gethostbyname2_r(name, AF_INET, result, buffer, buflen, errnop, h_errnop);  
}



// 在模块初始化函数中添加配置加载
void __attribute__((constructor)) init(void) {
    load_custom_networks();
    dns_log(LOG_INFO, "NSS module initialized");
}

// 在模块清理函数中释放资源
void __attribute__((destructor)) fini(void) {
    dns_log(LOG_INFO, "NSS module cleaned up");
}