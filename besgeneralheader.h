/*******************************************************************************
 *
 ********************* 程序文件:  BESGENERALHEADER        ***********************
 ********************* 程序编写:  LATIS                   ***********************
 ********************* 创建时间:  2010-05-24              ***********************
 ********************* 完成时间:  2010-05-28              ***********************
 ********************* 程序版本:  1.0.0                   ***********************
 *
 ******************************************************************************/
/*================================== 修改列表 ==================================//
 *
 *
 *
//================================== 修改结束 ==================================*/

#ifndef _BESGENERALHEADER_H
#define	_BESGENERALHEADER_H
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <iconv.h>
#include <math.h>
#include <signal.h>
#include <ctype.h>
#include <locale>
#include <unistd.h>
#include <sys/time.h>
#include <bits/stl_algo.h>
#include <sys/mount.h>
#include <iostream>
#include <exception>
#include <sstream>
#include <string>
#include <iomanip>
#include <vector>
#include <map>
#include <string>


using namespace std;

#define DEFAULT_BUFFER_SIZE                                 1024                        // 默认缓冲大小

#define SEPARATOR_CHAR_COMMA                                ','                         // 逗号
#define SEPARATOR_CHAR_SEMICOLON                            ';'                         // 分号
#define SEPARATOR_CHAR_COLON                                ':'                         // 冒号
#define SEPARATOR_CHAR_WELL                                 '#'                         // 井号
#define SEPARATOR_CHAR_SPACE                                ' '                         // 空格
#define SEPARATOR_CHAR_UNDERLINE                            '_'                         // 下划线
#define SEPARATOR_CHAR_MINUS_SIGN                           '-'                         // 减号
#define SEPARATOR_CHAR_PLUS_SIGN                            '+'                         // 加号
#define SEPARATOR_CHAR_SLASH                                '/'                         // 斜线
#define SEPARATOR_CHAR_BACKSLASH                            '\\'                        // 反斜线
#define SEPARATOR_CHAR_ASTERISK                             '*'                         // 星号
#define SEPARATOR_CHAR_DOT                                  '.'                         // 点
#define SEPARATOR_CHAR_EQUAL_SIGN                           '='                         // 等号
#define SEPARATOR_CHAR_GREATER_SIGN                         '>'                         // 大于号
#define SEPARATOR_CHAR_LESS_SIGN                            '<'                         // 小于号
#define SEPARATOR_CHAR_PIPE_SIGN                            '|'                         // 管道符
#define SEPARATOR_CHAR_REDIRECT_OUTPUT_SIGN                 (SEPARATOR_CHAR_GREATER_SIGN)   // 重定向输出
#define SEPARATOR_CHAR_REDIRECT_INPUT_SIGN                  (SEPARATOR_CHAR_LESS_SIGN)  // 重定向输入
#define SEPARATOR_CHAR_APPEND_REDIRECT_SIGN                 ">>"                        // 追加重定向
#define SEPARATOR_CHAR_MAIL                                 '@'                         // @
#define SEPARATOR_CHAR_COMMA_CHN                            "，"                        // 中文逗号
#define SEPARATOR_CHAR_COLON_CHN                            "："                        // 中文冒号

#define LINUX_PARAMETER_SEPCHAR                             (SEPARATOR_CHAR_SPACE)      // Linux参数分割符
#define LINUX_ROOT_CHAR                                     (SEPARATOR_CHAR_SLASH)      // Linux根标识符
#define LINUX_PATH_SEPCHAR                                  (SEPARATOR_CHAR_SLASH)      // Linux路径分割符
#define WINDOWS_PATH_SEPCHAR                                (SEPARATOR_CHAR_BACKSLASH)  // windows路径分割符
#define DEFAULT_C_STRING_END_FLAG                           '\0'                        // 默认c字符串结尾标识符

#define DEFAULT_LICENSE_EXTENSION                           ".lic"                      // 默认License文件扩展名
#define DEFAULT_LICENSE_INFO_FILE                           "licinfo.txt"               // 默认license信息文件
#define DEFAULT_CONFIG_FILE_NAME                            "bes.conf"                  // 默认配置文件名
#define DEFAULT_CONFIG_ITEM_HOST                            "HOST"                      // 配置项BES的ip
#define DEFAULT_CONFIG_ITEM_USER                            "USER"                      // 配置项数据库用户名
#define DEFAULT_CONFIG_ITEM_PASSWORD                        "PASSWORD"                  // 配置项数据库密码
#define DEFAULT_CONFIG_ITEM_DBNAME                          "DBNAME"                    // 配置项数据库名称
#define DEFAULT_CONFIG_ITEM_FCSERVER                        "FCSERVER"                  // 配置项存储服务器地址
#define DEFAULT_CONFIG_ITEM_LANG                            "LANG"                      // 配置项语言
#define DEFAULT_CONFIG_ITEM_TARGETBASE                      "TARGETBASE"                // 配置项target类型
#define DEFAULT_CONFIG_ITEM_MONITORUSER                     "MONITORUSER"               // 配置项监控的用户名
#define DEFAULT_CONFIG_ITEM_MONITORPWD                      "MONITORPWD"                // 配置项监控的密码
#define DEFAULT_CONFIG_ITEM_DBBACKUPNUM                     "DBBACKUPNUM"               // 配置项数据库备份个数
#define DEFAULT_CONFIG_ITEM_DRIVER_PATH                     "DRIVERPATH"                // 驱动目录
#define DEFAULT_CONFIG_ITEM_FILESYSTEM                      "FILESYSTEM"                // 配置项文件系统类型
#define DEFAULT_CONFIG_ITEM_AGENTTIMEOUT                    "AGENTTIMEOUT"              // 配置项agent超时时间（s）
#define DEFAULT_CONFIG_ITEM_CLEAN_CPNUMBER                  "CLEANCPNUM"                // 每次清理磁盘个数
#define DEFAULT_CONFIG_ITEM_IQN_PREFIX                      "IQNPREFIX"                 // iqn前缀
#define DEFAULT_CONFIG_ITEM_DATA_VOLUME_LABEL               "DATAVOLUMELABEL"           // 数据卷卷标
#define DEFAULT_CONFIG_ITEM_TARGET_DEVICE_TYPE              "TARGETDEVICETYPE"          // target设备类型

#define DEFAULT_CONFIG_ITEM_TIMING_SNAPSHOT_INTERVAL        "TIMINGSNAPSHOTINTERVAL"    // 定时快照时间
#define DEFAULT_MIN_TIMING_SNAPSHOT_INTERVAL                30                          // 默认最小定时快照时间
#define DEFAULT_MAX_TIMING_SNAPSHOT_INTERVAL                3600                        // 默认最大定时快照时间
#define DEFAULT_TIMING_SNAPSHOT_INTERVAL                    (DEFAULT_MIN_TIMING_SNAPSHOT_INTERVAL)                          // 定时快照时间间隔（s）

#define DEFAULT_CONFIG_ITEM_DEBUGLEVEL                      "DEBUGLEVEL"                // 调试信息级别
#define DEFAULT_DEBUG_LEVEL                                 3                           // 默认调试级别
#define DEFAULT_MIN_DEBUG_LEVEL                             1                           // 默认最小调试级别
#define DEFAULT_MAX_DEBUG_LEVEL                             5                           // 默认最大调试级别

#define DEFAULT_CONFIG_ITEM_LOCK_COPY                       "LOCKCOPY"                  // 锁定副本

#define DEFAULT_CONFIG_ITEM_AUTORUN_SCAN_TARGET             "AUTORUNSCANTARGET"         // 自动运行扫描target
#define DEFAULT_CONFIG_ITEM_AUTORUN_RDRTASKEXEC             "AUTORUNRDRTASKEXEC"        // 自动运行异地容灾任务执行器
#define DEFAULT_CONFIG_ITEM_AUTORUN_DRHDAEMON               "AUTORUNDRHDAEMON"          // 自动运行心跳守护进程

#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_EXEC_LOCAL_SHELL    "EXECLOCALSHELL"            // 是否执行本地shell
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_LOCAL_SHELL_NAME    "LOCALSHELLNAME"            // 本地脚本名
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_EXEC_NET_SHELL      "EXECNETSHELL"              // 是否执行网启shell
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_NET_SHELL_NAME      "NETSHELLNAME"              // 网启脚本名
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_EXEC_VM_SHELL       "EXECVMSHELL"               // 是否执行虚拟机shell
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_VM_SHELL_NAME       "VMSHELLNAME"               // 虚拟机脚本名
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_EXEC_FC_SHELL       "EXECFCSHELL"               // 是否执行光纤shell
#define DEFAULT_LINUX_AGENT_CONFIG_ITEM_FC_SHELL_NAME       "FCSHELLNAME"               // 光纤脚本名


#define DEFAULT_HOST_CODE_SIZE                              5                           // 默认主机编码长度
#define DEFAULT_SERVER_ID_SIZE                              3                           // 默认服务器编号长度

#define DEFAULT_BOOT_PROTOCOL_PXE                           "PXE"                       // 网启PXE协议
#define DEFAULT_BOOT_PROTOCOL_SNSBOOT                       "SNSBOOT"                   // 其他网启协议
#define DEFAULT_BOOT_PROTOCOL_HBA                           "HBA"                       // HBA卡网启协议
#define DEFAULT_BOOT_PROTOCOL_FCBOOT                        "FCBOOT"                    // 光纤卡网启协议
#define DEFAULT_BOOT_PROTOCOL_VMBOOT                        "VMBOOT"                    // 虚拟机启动协议

#define DEFAULT_OSTYPE_WINDOWS                              "100"                       // WINDOWS操作系统代码
#define DEFAULT_OSTYPE_WIN2K_XP_2K3                         "101"
#define DEFAULT_OSTYPE_WIN2K8                               "102"
#define DEFAULT_OSTYPE_LINUX                                "200"                       // LINUX操作系统代码
#define DEFAULT_OSTYPE_AIX                                  "300"                       // AIX操作系统代码
#define DEFAULT_OSTYPE_HPUX                                 "400"                       // HPUX操作系统代码

#define BES_AGENT_PORT                                      8585                        // 默认agent端口
#define BES_SERVER_PORT                                     8585                        // 默认server端口
#define BES_INTERNAL_PORT                                   8586                        // 内部通讯端口
#define MANAGE_PORT                                         8587                        // 管理端口
#define DEFAULT_WEB_VNC_PORT                                8686                        // web vnc监听端口
#define BES_RDR_PORT                                        9595                        // 默认RDR端口
#define DEFAULT_HEARTBEAT_PORT                              9090                        // 心跳监测端口
#define DEFAULT_MC_PORT                                     9696                        // mc接收数据端口
#define DEFAULT_MC_INTERNAL_PORT                            9697                        // mc内部端口

#define DEFAULT_LOG_UDP_PORT_BETASKEXEC                     8591                        // 任务执行器日志UDP端口
#define DEFAULT_LOG_UDP_PORT_BEDAEMON                       8592                        // 守护进程日志UDP端口
#define DEFAULT_LOG_UDP_PORT_RDRTASKEXEC                    8593                        // 异地容灾任务执行器UDP端口
#define DEFAULT_LOG_UDP_PORT_DRHDAEMON                      8594                        // 心跳守护进程UDP端口

#define DEFAULT_FC_SERVER_IP                                "10.10.10.253"              // FC存储服务器ip
#define DEFAULT_LOCALHOST_IP                                "127.0.0.1"                 // 默认本地ip

#define DEFAULT_GUI_BIN_PATH                                "/var/www/html/"            // 默认GUI路径
#define DEFAULT_UPGRADE_ZIP_PATH                            "/var/www/html/upload/"     // 默认升级包路径
#define DEFAULT_BACKUP_DIRECTORY                            "/oldversion/"              // 默认备份目录名
#define DEFAULT_BACKUP_FILE_SUFFIX                          "_bak"

#define DEFAULT_ZIP_FILE_EXTENSION                          ".zip"                      // zip文件扩展名
#define DEFAULT_TAR_FILE_EXTENSION                          ".tar"                      // tar文件扩展名
#define DEFAULT_XML_FILE_EXTENSION                          ".xml"                      // xml文件扩展名
#define DEFAULT_CONFIG_FILE_EXTENSION                       ".conf"                     // 配置文件扩展名
#define DEFAULT_PID_FILE_EXTENTSION                         ".pid"                      // pid文件扩展名


#define HOST_ACTION_STARTVM                                 "STARTVM"                   // 主机动作启动虚拟机
#define HOST_ACTION_STOPVM                                  "STOPVM"                    // 主机动作启动虚拟机

#define DEFAULT_SOCKET_CONNECT_TIMEOUT                      10                          // 默认socket连接超时(s)

#define DEFAULT_DATABASE_BACKUP_NUM                         5                           // 默认数据库备份文件个数
#define DEFAULT_INVALID_RETURN_VALUE                        "?"                         // 默认无效返回值
#define DEFAULT_INVALID_RETURN_VALUE2                       "-"                         // 默认无效返回值
#define DEFAULT_EMPTY_STRING                                ""                          // 空字符串

#define DEFAULT_SERVICE_NAME_DHCP                           "dhcpd"                     // 默认dhcp服务名
#define DEFAULT_SERVICE_NAME_EMBOOT                         "emnbid"                    // 默认emboot服务名
#define DEFAULT_SERVICE_NAME_STGT                           "tgtd"                      // 默认stgt服务名
#define DEFAULT_SERVICE_NAME_SCST                           "iscsi-scst"                // 默认scst服务名
#define DEFAULT_SERVICE_NAME_HTTP                           "httpd"                     // 默认http服务名
#define DEFAULT_SERVICE_NAME_MYSQL                          "mysqld"                    // 默认mysql服务名
#define DEFAULT_SERVICE_NAME_XINETD                         "xinetd"                    // 默认xinetd服务名
#define DEFAULT_SERVICE_NAME_ISCSID                         "iscsid"                    // 默认iscsid服务名
#define DEFAULT_SERVICE_NAME_VNC                            "vncserver"                 // 默认vnc服务名
#define DEFAULT_SERVICE_NAME_VNC_ALIAS                      "Xvnc"                      // 默认vnc服务别名
#define DEFAULT_SERVICE_NAME_KVM                            "libvirtd"                  // 默认kvm服务名
#define DEFAULT_SERVICE_NAME_NETWORK                        "network"                   // 默认network服务名
#define DEFAULT_SERVICE_NAME_SSH                            "sshd"                      // 默认ssh服务名

#define DEFAULT_DIR_PERMISSION                              (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) // 默认目录权限
#define DEFAULT_FILE_PERMISSION                             (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) // 默认文件权限
#define DEFAULT_FULL_PERMISSION                             (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) // 777权限

#define DEFAULT_FILESYSTEM_TYPE_BTRFS                       "btrfs"                     // 默认文件系统类型btrfs
#define DEFAULT_FILESYSTEM_TYPE_NILFS2                      "nilfs2"                    // 默认文件系统类型nilfs2
#define DEFAULT_FILESYSTEM_TYPE_FAT32                       "fat32"                     // 默认文件系统类型fat32
#define DEFAULT_FILESYSTEM_TYPE_NTFS                        "ntfs"                      // 默认文件系统类型ntfs
#define DEFAULT_FILESYSTEM_TYPE_NTFS_3G                     "ntfs-3g"                   // 默认文件系统类型ntfs
#define DEFAULT_FILESYSTEM_TYPE_RAW                         "raw"                       // 默认文件系统类型raw
#define DEFAULT_FILESYSTEM_TYPE_EXT3                        "ext3"                      // 默认文件系统类型ext3
#define DEFAULT_FILESYSTEM_TYPE_EXT4                        "ext4"                      // 默认文件系统类型ext4
#define DEFAULT_FILESYSTEM_TYPE_REISERFS                    "reiserfs"                  // suse文件系统类型
#define DEFAULT_FILESYSTEM_TYPE_ZFS                         "zfs"                       // 默认文件系统类型zfs

#define DEFAULT_DB_BACKUP_VIRTUAL_SYMBOL                    "DB"                        // 默认数据库备份虚拟盘符

#define DEFAULT_WINDOWS_SYSTEM_FLAG                         "C"                         // 默认windows系统标识
#define DEFAULT_LINUX_SYSTEM_FLAG                           "/"                         // 默认linux系统标识
#define DEFAULT_AIX_SYSTEM_FLAG                             "rootvg"                    // 默认aix系统标识


#define DEFAULT_SW_SERVER_BETASKEXEC                        "BETaskExec"
#define DEFAULT_SW_SERVER_BEDAEMON                          "BEDaemon"
#define DEFAULT_SW_SERVER_BEUPGRADE                         "BEUpgrade"
#define DEFAULT_SW_SERVER_RDRTASKEXEC                       "RdrTaskExec"
#define DEFAULT_SW_SERVER_DRHDAEON                          "Drhdaemon"
#define DEFAULT_SW_GUI                                      "GUI"

// 目录定义
#define DEFAULT_TEMP_PATH                                   "/tmp/"                     // 默认临时文件目录
#define DEFAULT_SYSTEM_SERVICE_PATH                         "/etc/init.d/"              // 默认系统服务目录
#define DEFAULT_SBIN_PATH                                   "/sbin/"                    // /sbin目录
#define DEFAULT_USR_SBIN_PATH                               "/usr/sbin/"                // /usr/sbin目录
#define DEFAULT_USR_BIN_PATH                                "/usr/bin/"                 // /usr/bin目录
#define DEFAULT_USR_LOCAL_SBIN_PATH                         "/usr/local/sbin/"          // /usr/local/sbin/目录
#define DEFAULT_USR_LOCAL_BIN_PATH                          "/usr/local/bin/"           // /usr/local/bin/目录
#define DEFAULT_USR_LIB64_PATH                              "/usr/lib64/"               // /usr/lib64/目录
#define DEFAULT_VAR_RUN_PATH                                "/var/run/"                 // /var/run/目录

#define DEFAULT_PHPMYADMIN_PATH                             "/var/www/html/phpMyAdmin"  // phpMyAdmin目录

#define DEFAULT_DYNAMIC_LINKER_PREFIX                       "lib"                       // 动态链接库前缀
#define DEFAULT_DYNAMIC_LINKER_FILE_EXTENSION               ".so"                       // 动态链接库文件扩展名
#define DEFAULT_DYNAMIC_LINKER_ZWLICENSE                    "zwlicense"                 // 动态链接库名

#define DEFAULT_FC_NAME_PREFIX                              "fc"                        // 光纤卡名称前缀

#define DEFAULT_CHINESE_LANG_ID                             "CN"                        // 默认中文id
#define DEFAULT_ENGLISH_LANG_ID                             "EN"                        // 默认英文id

#define DEFAULT_SELF_CHECK_LOG_FILE_NAME                    "zwselfcheck.log"           // 自检日志文件名

#define INTERNAL_EXIT_COMMAND                               "EXITTIXE"                  // 内部退出命令

#define DEFAULT_MC_HOST_DATA_PREFIX                         "MC@H"                      //
#define DEFAULT_MC_TASK_DATA_PREFIX                         "MC@T"                      //

#define DEFAULT_DEVICE_MINOR_MIN                            1                           // 最小设备号
#define DEFAULT_DEVICE_MINOR_MAX                            255                         // 最大设备号

// MBR宏定义
#define DEFAULT_MBR_SECTOR_OFFSET                           461                         // 默认MBR扇区偏移量
#define DEFAULT_MBR_SIGNATURE_OFFSET                        440                         // 默认MBR扇区偏移量
#define DEFAULT_MBR_PARTITION_OFFSET                        446                         // MBR分区偏移量
#define DEFAULT_MBR_PARTITION_LENGTH                        16                          // MBR分区长度（字节数）
#define DEFAULT_MBR_PARTITION_FILESYSTEM_OFFSET             4                           // MBR中分区文件系统偏移量

// 调试宏
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define DEBUGARGS                                           (string(__FILE__)+string("(")+string(TOSTRING(__LINE__))+string("):")+string(__FUNCTION__)+string("-->"))

// 基础文件系统

enum BaseFileSystem
{
    BASE_FILESYSTEM_UNKNOWN,
    BASE_FILESYSTEM_BTRFS,
    BASE_FILESYSTEM_NILFS2,
    BASE_FILESYSTEM_FAT32,
    BASE_FILESYSTEM_NTFS,
    BASE_FILESYSTEM_RAW,
    BASE_FILESYSTEM_EXT3,
    BASE_FILESYSTEM_EXT4,
    BASE_FILESYSTEM_REISERFS,
    BASE_FILESYSTEM_ZFS,
};

// 描述语言

enum DescriptionLang
{
    DESCRIPTION_LANG_EN,
    DESCRIPTION_LANG_CN,
};

#ifdef _DEBUG_VERSION_
#undef   _DEBUG_VERSION_
#endif

//#ifndef _DEBUG_VERSION_
//#define   _DEBUG_VERSION_
//#endif

#endif	/* _BESGENERALHEADER_H */

