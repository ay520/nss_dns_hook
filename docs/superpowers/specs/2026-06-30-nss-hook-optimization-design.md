# NSS DNS Hook 模块优化设计

- 日期: 2026-06-30
- 范围: 现有 `nss_dns_hook` 项目的代码优化与重构,不改变对外行为语义
- 目标: 修复严重 bug、提升性能、改善可维护性,为后续 exe 维度策略等扩展打基础

## 1. 背景与问题

现有 `nss_dns_hook` 是一个基于 glibc NSS 的 DNS hook 模块(`libnss_hs.so.2`),通过 `/etc/nsswitch.conf` 的 `hosts: files hs dns` 在系统 DNS 之前拦截解析。处置逻辑:解析返回的内网 IP 放行,公网 IP 按域名白名单比对,在白名单内放行,否则劫持到 `127.0.0.1` / `::1`。

当前实现存在以下问题:

1. **白名单每次查询都加载+销毁**(`nss_module.c:516, 594`),`load_whitelist` / `cleanup_whitelist` 在每次 `_nss_hs_gethostbyname4_r` 调用中执行,文件 I/O + 哈希构建 + 释放开销大
2. **线程不安全**:全局 `whitelist_hash` 无锁保护,多线程并发解析会崩溃或 double-free
3. **通配符匹配不完整**(`nss_module.c:299-322`):只查找第一级父域名的 `*.suffix`,`a.b.baidu.com` 无法匹配白名单中的 `*.baidu.com`
4. **无 DNS 缓存**:每次查询都打上游
5. **`res_ninit` / `res_nclose` 每次调用**(`nss_module.c:523, 591`)
6. **日志每次 fopen/fclose**(`dns_log.c:34`),`localtime` 非线程安全,`/var/log` 写权限问题
7. **`#include "get_cmdchain.c"`**(`nss_module.c:20`):应独立编译
8. **`get_cmdchain.c` 多处 bug**:`read_proc_path` readlink 失败返回未初始化 buffer;`get_file_length` 逐字符读;`get_proc_stat` 的 `fscanf` 遇含空格进程名会断;`read_cmdline` 双 \0 计数逻辑脆弱
9. **`MAX_WHITELIST_ENTRIES` 边界 off-by-one**(`nss_module.c:287`):`count > MAX` 应为 `>=`
10. **未用代码**:`get_cmd_chain` / `get_proc_stat` 等暂未在主流程使用(本轮保留,后续 exe 维度策略会用)

## 2. 架构与文件结构

### 2.1 目录结构

```
nss_dns_hook/
├── Makefile                    # SRCS 加入 whitelist.c dns_cache.c proc_info.c
├── nss_module.c                # 4 个 NSS 入口 + 地址转换 + 网络判定 (瘦身到 ~350 行)
├── whitelist.h
├── whitelist.c                 # 加载/查找/mtime 重载/RWLock
├── dns_cache.h
├── dns_cache.c                 # LRU+TTL/RWLock
├── proc_info.h                 # 暴露 read_cmdline/read_proc_path/get_cmd_chain 等
├── proc_info.c                 # 从 get_cmdchain.c 改名,修 bug,保留全部函数
├── dns_log.h
├── dns_log.c                   # syslog(LOG_LOCAL0) 封装
├── uthash.h                    # 不动
├── nss_whitelist.conf          # 不动
└── nss_private_networks.conf   # 不动
```

### 2.2 模块依赖(单向,无环)

```
nss_module.c
  ├── proc_info   (只读 cmdline/exe,日志用)
  ├── whitelist   (策略决策)
  ├── dns_cache   (命中跳过 res_nquery)
  └── dns_log     (贯穿所有模块)

proc_info.c → dns_log
whitelist.c → dns_log, uthash
dns_cache.c → dns_log, uthash
```

模块间无共享锁,不会死锁。每个模块自管自己的全局状态和锁。

### 2.3 数据流(一次 `_nss_hs_gethostbyname4_r` 调用)

```
入口
  ├─ dns_log 记录 name + pid + cmdline + exe  (proc_info 提供)
  ├─ whitelist_check_mtime()  → 必要时加写锁重载
  ├─ if (!whitelist_is_loaded()) return NSS_STATUS_NOTFOUND  (fail-open)
  ├─ dns_cache_get(name)
  │    ├─ 命中且未过期 → 用缓存的 answer 字节重新 parse → add_ipv4/6_address → 返回
  │    └─ 未命中/过期 → 继续
  ├─ res_nquery A + AAAA (仅 miss 路径)
  ├─ parse_answer_and_add → 对每个 IP: is_private_ip + whitelist_match 决策
  ├─ dns_cache_put(name, answer, ttl) (仅 miss 路径)
  └─ 返回
```

劫持决策(`is_private_ip` + `whitelist_match`)在 `add_ipv4_address` / `add_ipv6_address` 内部,cache 命中时也走这段。所以白名单更新后,即便缓存里有旧查询结果,劫持决策仍按最新白名单走——缓存只省上游 DNS 查询,不影响策略。

## 3. whitelist 模块

### 3.1 数据结构

```c
struct whitelist_entry {
    char *domain;        // 配置文件原文,如 "*.baidu.com" 或 "github.com"
    int is_wildcard;     // 是否以 * 开头(保留字段,逐级匹配不依赖它)
    UT_hash_handle hh;
};

static struct whitelist_entry *whitelist_hash = NULL;
static time_t whitelist_mtime = 0;
static pthread_rwlock_t whitelist_lock = PTHREAD_RWLOCK_INITIALIZER;
static int whitelist_count = 0;
```

### 3.2 接口

```c
// 首次加载(constructor 调用),内部加写锁
void whitelist_initial_load(void);

// mtime 检查,变了就重载(每次查询入口调用)
void whitelist_check_mtime(void);

// 查找:精确 + 逐级通配符,持读锁
int whitelist_match(const char *domain);

// 白名单是否非空。返回 whitelist_count > 0 ? 1 : 0(用于 fail-open 判断)
int whitelist_is_loaded(void);

// 析构释放(destructor 调用)
void whitelist_destroy(void);
```

### 3.3 加载策略:先建新表再替换

`whitelist_reload_locked`(持写锁时调用)流程:

1. 读取文件,逐行 parse,构建 `new_hash`
2. 若中途 parse 失败 → 丢弃 `new_hash`,保留旧 hash,记 WARNING,返回 -1
3. 成功 → cleanup 旧 hash,`whitelist_hash = new_hash`,更新 mtime 和 count

避免 reload 期间出现"哈希为空"的窗口。

### 3.4 mtime 检查(无锁快速路径)

```c
void whitelist_check_mtime(void) {
    struct stat st;
    if (stat(WHITELIST_FILE, &st) != 0) return;
    if (st.st_mtime == whitelist_mtime) return;

    pthread_rwlock_wrlock(&whitelist_lock);
    // double-check:拿到写锁后再 stat,避免并发重复重载
    if (stat(WHITELIST_FILE, &st) == 0 && st.st_mtime != whitelist_mtime) {
        whitelist_reload_locked();
    }
    pthread_rwlock_unlock(&whitelist_lock);
}
```

- 无锁路径:一次 `stat` + 整数比较,~1μs
- 写锁路径:仅 mtime 真的变化时进入,double-check 避免并发重复重载

### 3.5 逐级通配符匹配

```c
int whitelist_match(const char *domain) {
    pthread_rwlock_rdlock(&whitelist_lock);

    struct whitelist_entry *e;
    HASH_FIND_STR(whitelist_hash, domain, e);     // 1. 精确匹配
    if (e) { unlock; return 1; }

    // 2. 逐级剥标签:对 a.b.baidu.com 依次试 *.b.baidu.com, *.baidu.com, *.com
    const char *p = domain;
    while ((p = strchr(p, '.')) != NULL) {
        char wildcard[MAX_DOMAIN_LENGTH];
        snprintf(wildcard, sizeof(wildcard), "*%s", p);
        HASH_FIND_STR(whitelist_hash, wildcard, e);
        if (e) { unlock; return 1; }
        p++;
    }

    pthread_rwlock_unlock(&whitelist_lock);
    return 0;
}
```

语义:`*.baidu.com` 匹配 `www.baidu.com`、`a.b.baidu.com`,但**不**匹配 `baidu.com` 本身(需白名单单独列 `baidu.com`)——与 README 的双列法一致。

### 3.6 fail-open 语义

白名单为空/缺失时:`whitelist_is_loaded()` 返回 0 → `_nss_hs_gethostbyname4_r` 返回 `NSS_STATUS_NOTFOUND` → 下游 `dns` 模块接管。这与当前代码行为一致,避免配置出错时把整台机器 DNS 打死。

### 3.7 边界修复

- `MAX_WHITELIST_ENTRIES` 检查改为 `count >= MAX`,在 add 前判断(修 off-by-one)
- parse 失败的行跳过并记 WARNING,不中断加载

## 4. dns_cache 模块

### 4.1 数据结构

```c
struct cache_entry {
    char *domain;              // key
    unsigned char *answer_a;   // A 记录原始 DNS 响应 (NULL 表示负缓存)
    size_t answer_a_len;
    unsigned char *answer_aaaa;
    size_t answer_aaaa_len;
    time_t expires_at;         // 绝对过期时间戳
    int negative_a;
    int negative_aaaa;
    UT_hash_handle hh;
    struct cache_entry *lru_prev, *lru_next;
};

static struct cache_entry *cache_hash = NULL;
static struct cache_entry *lru_head = NULL;    // 最近使用
static struct cache_entry *lru_tail = NULL;    // 最久未使用
static size_t cache_count = 0;
static pthread_rwlock_t cache_lock = PTHREAD_RWLOCK_INITIALIZER;
```

### 4.2 参数

- 容量: 512 条
- 正缓存 TTL: `min(响应里所有记录的最小 TTL, 300s)`
- 负缓存 TTL: 30s 固定
- 缓存对象: 原始 DNS 响应字节(不缓存解析后的 `gaih_addrtuple` 链表,避免序列化)
- A 和 AAAA 分开存储,负缓存独立

### 4.3 接口

```c
// 查询。命中且未过期返回 1,把 answer 指针/长度/negative 写回 out;否则返回 0
int dns_cache_get(const char *domain,
                  unsigned char **out_a, size_t *out_a_len, int *out_neg_a,
                  unsigned char **out_aaaa, size_t *out_aaaa_len, int *out_neg_aaaa);

// 写入。内部 malloc + memcpy,调用方传进来的 answer 仍归调用方
void dns_cache_put(const char *domain,
                   const unsigned char *answer_a, size_t a_len, int neg_a, int ttl_a,
                   const unsigned char *answer_aaaa, size_t aaaa_len, int neg_aaaa, int ttl_aaaa);

// 析构释放
void dns_cache_destroy(void);
```

### 4.4 LRU 策略(近似 LRU)

- `dns_cache_get` 命中时**不在读锁下移动 LRU 节点**(否则每次命中都要写锁,RWLock 失去意义)
- 只在 `dns_cache_put` 插入/更新时把条目移到 head
- 这是 "FIFO + 重新插入" 近似 LRU,对 DNS 缓存足够:热点域名会被反复 put,冷域名自然沉到 tail

### 4.5 流程

**`dns_cache_get`(读锁):**

```
rdlock
  HASH_FIND_STR(domain)
  if not found → unlock, return 0
  if time() >= expires_at → unlock, return 0   (过期条目不在 get 时删,留给 put 时 sweep)
  if fresh → 拷贝 answer 指针/长度/negative 到 out → unlock → return 1
```

**`dns_cache_put`(写锁):**

```
wrlock
  1. sweep:遍历 hash,删除所有过期条目(从 LRU 链表和 hash 摘掉,free)
  2. HASH_FIND_STR 看是否已有条目
     有 → 更新 answer/negative/expires,移到 LRU head
     无 → 新建条目,插到 LRU head
  3. 若 cache_count > 512 → 从 lru_tail 淘汰,直到 <= 512
  unlock
```

### 4.6 并发与 thundering herd

- 多线程同时 `dns_cache_get` 同一域名 → 都拿读锁,都命中,都返回同一份 answer 指针。调用方只用 `memcpy` 读,安全
- 多线程同时 miss 同一域名 → 都去 `res_nquery`,然后都 `dns_cache_put`,最后一个覆盖前面的。无正确性问题,仅浪费一次上游查询
- **不做 singleflight**:DNS 查询便宜(一个 UDP 包),重复窗口只在冷缓存首查时出现,引入条件变量/等待队列的复杂度收益不划算

### 4.7 内存管理

`dns_cache_put` 内部 `malloc` + `memcpy` 一份,调用方传进来的 `answer` 仍归调用方(在 `nss_module.c` 里是栈上 `unsigned char answer[NS_MAXMSG]`)。接口清晰,调用方不用想内存管理。

## 5. proc_info 模块(从 get_cmdchain.c 改名)

### 5.1 文件操作

- `get_cmdchain.c` → `proc_info.c`
- 新建 `proc_info.h`,声明所有对外函数和结构体

### 5.2 接口(全部保留,不删函数)

```c
struct proc_stat;          // 原结构体,不动
struct cmd_chain_struct;   // 原结构体,不动

char *read_cmdline(int pid);                       // 调用方 free
char *read_proc_path(int pid);                     // 调用方 free
struct proc_stat get_proc_stat(int pid);
long get_file_length(char *path);
void get_cmd_chain(int pid, struct cmd_chain_struct *out);
```

### 5.3 bug 修复(不改功能语义)

1. **`read_proc_path` readlink 失败返回未初始化 buffer**:`malloc` 后立刻 `memset` 清零,readlink 失败时返回空串(非 NULL,调用方仍能 free)
2. **`get_file_length` 逐字符 getc**:改用 `fseek(SEEK_END)` + `ftell`,O(1)
3. **`get_proc_stat` 的 `fscanf("(%99s ")` 遇含空格进程名断**:改 `fgets` 整行,手动找最后一个 `)`,提取括号内字符串作 `comm`
4. **`read_cmdline` 双 \0 计数逻辑脆弱**:简化为"读整个文件到 buffer → 把所有 \0 替换成空格 → 去掉尾部多余空格",逻辑等价但清晰
5. **`read_cmdline` 文件长度为 0 时**:直接返回空串,不 `malloc(1)` 后 `memset`

### 5.4 不动的部分

`cmd_chain_struct`、`proc_stat` 结构体定义、`get_cmd_chain` 的算法逻辑、所有函数签名。后续 exe 维度策略会用到 `get_cmd_chain`。

## 6. dns_log 模块(syslog 封装)

### 6.1 接口

```c
#define LOG_INFO    6
#define LOG_WARNING 4
#define LOG_ERROR   3
#define LOG_DEBUG   7    // 新增,用于详细调试日志

void dns_log(int log_level, const char *format, ...);
// set_log_file 删除(syslog 模式下无意义)
```

### 6.2 实现

```c
#include <syslog.h>
#include <stdarg.h>

void dns_log(int log_level, const char *format, ...) {
    int priority;
    switch (log_level) {
        case LOG_INFO:    priority = LOG_INFO;    break;
        case LOG_WARNING: priority = LOG_WARNING; break;
        case LOG_ERROR:   priority = LOG_ERR;     break;  // LOG_ERROR 映射到 LOG_ERR
        case LOG_DEBUG:   priority = LOG_DEBUG;   break;
        default:          priority = LOG_DEBUG;
    }
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}
```

### 6.3 openlog / closelog

放在 `nss_module.c` 的 constructor/destructor:

```c
openlog("nss_hs", LOG_NDELAY | LOG_PID | LOG_CONS, LOG_LOCAL0);
// ...
closelog();
```

- `LOG_PID`:每条日志带 PID(对 NSS 模块特别有用)
- `LOG_CONS`:syslogd 不可达时写 console,避免日志丢失
- `LOG_LOCAL0`:facility,路由到单独文件

### 6.4 调试日志开关

详细日志(`print_address` / `print_address_list` 的逐条地址打印)优先级从 `LOG_INFO` 改为 `LOG_DEBUG`。操作日志(域名 hook 入口、劫持决策、错误)保持 `LOG_INFO` / `LOG_WARNING` / `LOG_ERROR`。

| 场景 | 行为 |
|------|------|
| 默认 rsyslog `*.info` | `LOG_DEBUG`(7)低于 info(6),被丢弃 → 详细日志关 |
| 调试:`local0.debug /var/log/nss_hs.log` | debug 也捕获 → 详细日志开 |
| journald:`journalctl -t nss_hs -p debug` | 只看 debug → 详细日志可见 |
| 不配 local0 路由 | debug 被 `*.info` 过滤,info/warn/err 仍进 messages |

零代码运行时开销,不用 env var / 全局变量 / 配置文件,切换只需改 syslog 配置。

## 7. nss_module.c 集成

### 7.1 头文件替换

```c
// 删除
#include "get_cmdchain.c"
// 新增
#include "proc_info.h"
#include "whitelist.h"
#include "dns_cache.h"
```

### 7.2 迁移与保留

**迁移到 whitelist.c:** `struct whitelist_entry`、`whitelist_hash`、`load_whitelist`、`is_domain_whitelisted`、`cleanup_whitelist`

**保留在 nss_module.c:**
- `parse_cidr`、`generate_ipv6_mask`、`is_private_ip`、`custom_networks`、`load_custom_networks` —— 网络判定逻辑,和 NSS 入口耦合紧密
- `print_address`、`print_address_list`(改用 `LOG_DEBUG`)、`safe_allocate`、`add_ipv4_address`、`add_ipv6_address`
- 4 个 NSS 入口函数

### 7.3 新增解析辅助函数

```c
// 从 answer buffer 解析 A 或 AAAA 记录,加到 pat 链表,顺便提取最小 TTL
// 返回新增地址数(addr_count 的增量);-1 表示解析失败(ns_initparse/ns_parserr 错误)
static int parse_answer_and_add(
    struct buffer_data *buf,
    const unsigned char *answer, int answer_len,
    int af,                          // AF_INET → ns_t_a, AF_INET6 → ns_t_aaaa
    struct gaih_addrtuple **pat,
    struct gaih_addrtuple **prev,
    int *addr_count,
    const char *domain,
    int *out_min_ttl
);
```

把现有 `ns_initparse` + `ns_parserr` 循环提取出来,加上 `ns_rr_ttl(rr)` 取 TTL 求 min。cache 命中和 miss 两条路径都调它,代码不重复。

### 7.4 `_nss_hs_gethostbyname4_r` 新流程

```
1. 日志:read_cmdline + read_proc_path + dns_log(LOG_INFO, ...)
2. whitelist_check_mtime()
3. if (!whitelist_is_loaded()) return NSS_STATUS_NOTFOUND   (fail-open)
4. cache_hit = dns_cache_get(name, &a, &a_len, &neg_a, &aaaa, &aaaa_len, &neg_aaaa)
5. 初始化 buffer_data, addr_count=0, prev=NULL
   min_ttl_a = DEFAULT_TTL, min_ttl_aaaa = DEFAULT_TTL
6. if (cache_hit) {
      if (a && a_len > 0)
          parse_answer_and_add(&buf, a, a_len, AF_INET, pat, &prev, &addr_count, name, &min_ttl_a);
      if (aaaa && aaaa_len > 0)
          parse_answer_and_add(&buf, aaaa, aaaa_len, AF_INET6, pat, &prev, &addr_count, name, &min_ttl_aaaa);
   } else {
      res_ninit(&res)
      len_a = res_nquery(..., T_A, answer, sizeof(answer))
      if (len_a > 0) parse_answer_and_add(..., AF_INET, ..., &min_ttl_a);
      else neg_a_local = 1;

      len_aaaa = res_nquery(..., T_AAAA, answer, sizeof(answer))
      if (len_aaaa > 0) parse_answer_and_add(..., AF_INET6, ..., &min_ttl_aaaa);
      else neg_aaaa_local = 1;

      res_nclose(&res)

      dns_cache_put(name,
                    len_a > 0 ? answer : NULL, len_a, neg_a_local, min_ttl_a,
                    len_aaaa > 0 ? answer : NULL, len_aaaa, neg_aaaa_local, min_ttl_aaaa);
   }
7. if (addr_count == 0) return NSS_STATUS_NOTFOUND
8. *ttlp = DEFAULT_TTL; return NSS_STATUS_SUCCESS
```

### 7.5 其他三个入口函数

`_nss_hs_gethostbyname3_r` / `_nss_hs_gethostbyname2_r` / `_nss_hs_gethostbyname_r` 不变,继续委托给 `_nss_hs_gethostbyname4_r`。只重构 byname4_r。

### 7.6 constructor / destructor

```c
void __attribute__((constructor)) init(void) {
    openlog("nss_hs", LOG_NDELAY | LOG_PID | LOG_CONS, LOG_LOCAL0);
    load_custom_networks();
    whitelist_initial_load();
    dns_log(LOG_INFO, "NSS module initialized");
}

void __attribute__((destructor)) fini(void) {
    whitelist_destroy();
    dns_cache_destroy();
    closelog();
}
```

## 8. Makefile 改动

```makefile
SRCS = nss_module.c whitelist.c dns_cache.c proc_info.c dns_log.c
# LDFLAGS 的 -lpthread -lresolv 已有,不变
```

## 9. 错误处理与线程安全

### 9.1 线程安全

- `whitelist_lock`(RWLock):读操作(`whitelist_match`、`whitelist_is_loaded`)用读锁,写操作(`whitelist_reload_locked`)用写锁
- `cache_lock`(RWLock):`dns_cache_get` 用读锁,`dns_cache_put` 用写锁
- `custom_networks` 在 constructor 加载后只读,无需锁
- `openlog` / `closelog` 在 constructor/destructor 调用,`vsyslog` 内部线程安全
- 模块间无共享锁,无锁顺序问题,不会死锁

### 9.2 错误处理

- 白名单文件缺失/空 → fail-open(返回 NOTFOUND 给下游)
- 白名单 parse 失败的行 → 跳过并记 WARNING,不中断加载
- 白名单整体 reload 失败 → 保留旧 hash,记 WARNING
- 缓存 malloc 失败 → 记 WARNING,该条不缓存(不影响查询,只是 cache miss)
- `res_nquery` 失败 → 走负缓存路径
- `res_ninit` 失败 → 返回 `NSS_STATUS_UNAVAIL` + EAGAIN

## 10. 测试策略

### 10.1 编译验证

在 Linux 开发环境(`8.155.31.213`,SSH 证书 `/Users/wukong/dnshook/wukong.pem`)上:
- `make clean && make` 编译通过,无 warning(`-Wall -Wextra`)
- `make install` 安装到 `/lib64/`,`ldconfig` 识别

### 10.2 单元测试(可选,如果时间允许)

- whitelist 模块:加载、逐级通配符匹配、mtime 重载、fail-open
- dns_cache 模块:put/get、TTL 过期、LRU 淘汰、负缓存

可以写一个简单的 `test_whitelist.c` / `test_dns_cache.c`,链接对应的 `.o`,不依赖 NSS 框架。

### 10.3 集成测试

在 Linux 环境:
1. 配置 `/etc/nsswitch.conf` 的 `hosts: files hs dns`
2. 配置 `/etc/nss_whitelist.conf`(用现有的)
3. `getent hosts www.baidu.com` → 应返回真实 IP(白名单内)
4. `getent hosts evil.example.com` → 应返回 127.0.0.1(劫持)
5. `getent hosts a.b.baidu.com` → 应返回真实 IP(逐级通配符匹配 `*.baidu.com`)
6. 修改 `/etc/nss_whitelist.conf`,mtime 变化后下次查询应反映新规则
7. 多线程测试:短时间并发 `getent hosts` × N,无崩溃
8. 缓存验证:同一域名连续 `getent` 多次,`tcpdump` 观察上游 DNS 查询应只发生一次(后续命中缓存)

### 10.4 日志验证

- `journalctl -t nss_hs` 或 `grep nss_hs /var/log/messages` 看到 INFO 级日志
- 配置 `local0.debug` 后能看到 DEBUG 级详细地址列表

## 11. 部署配套

### 11.1 rsyslog 配置(可选)

`/etc/rsyslog.d/nss_hs.conf`:
```
local0.*    /var/log/nss_hs.log
& stop
```
`systemctl restart rsyslog`。不配也能用,日志混进 `/var/log/messages`。

### 11.2 nsswitch 配置

`/etc/nsswitch.conf` 的 `hosts` 行:
```
hosts: files hs dns
```

### 11.3 README 更新

更新 README,补充:
- syslog 日志说明(facility `local0`,ident `nss_hs`)
- rsyslog 配置示例(可选)
- 调试日志开启方法(`local0.debug` 或 `journalctl -p debug`)
- mtime 热加载说明(改完白名单立即生效,无需重启)

## 12. 不在本轮范围

- exe 维度策略(按进程路径做不同 DNS 策略)—— 后续单独一轮
- singleflight(并发 miss 去重)—— 收益不划算
- DNS-over-HTTPS/TLS 支持 —— 超出 NSS 模块能力范围
- 跨进程共享缓存 —— NSS 模块天然 per-process,共享需 mmap + 跨进程锁,复杂度大
