# 指定编译器
CC = gcc

# 编译选项 -Wall -Wextra 用于显示所有警告信息，-fPIC 用于生成位置独立代码（共享库需要）
CFLAGS = -fPIC -Wall -Wextra

# 链接选项 -shared 表示生成共享库，-Wl,-soname,... 用于定义库的 soname
LDFLAGS = -shared -Wl,-soname,libnss_hs.so.2  -lpthread -lresolv

# 目标文件库的实际名称
TARGET = libnss_hs.so.2

# 源文件列表
SRCS = nss_module.c dns_log.c

# 由源文件生成的对象文件列表
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接生成共享库
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

# 编译规则，将 .c 文件编译成 .o 文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目标
clean:
	rm -f $(OBJS) $(TARGET)

# 安装目标
install: $(TARGET)
	install -m 0755 $(TARGET) /lib64/
	ldconfig

# 卸载目标
uninstall:
	rm -f /lib64/$(TARGET)
	ldconfig
