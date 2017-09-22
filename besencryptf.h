/*******************************************************************************
 *
 ********************* 程序文件:  BesEncryptF             ***********************
 ********************* 程序编写:  LATIS                   ***********************
 ********************* 创建时间:  2010-06-03              ***********************
 ********************* 完成时间:  2010-06-03              ***********************
 ********************* 程序版本:  1.0.0                   ***********************
 *
 ******************************************************************************/
/*================================== 修改列表 ==================================//
 *
 *20101021  LATIS   1)修复了获取磁盘序列号和大小时出现多条记录的bug
 *20101105  LATIS   1)修复了获取磁盘序列号时出现的分区无法获取序列号的bug
 *20110421  LATIS   1)修改了DiskSerialNo方法中获取磁盘序列号机制，支持raid卡上的分区方式
 *20110421  LATIS   2)在DiskSize方法中，由读取整个磁盘大小，更改为读取分区大小
 *20110504  LATIS   1)修改了DiskSize和DiskSerialNo方法中读取配置文件的方法
 *20120405  LATIS   1)增加了GetBootDevice方法
 *20121217  latis   1)增加了授权模式
 *                  2)增加了授权类型
 *
//================================== 修改结束 ==================================*/

#ifndef _BESENCRYPTF_H
#define	_BESENCRYPTF_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <math.h>
//#include "begenerallib.h"
#include "besgeneralheader.h"

class BesEncryptF
{
public:
    BesEncryptF();
    virtual ~BesEncryptF();
public:

    // 授权类型
    enum LicenseType
    {
        LICENSE_TYPE_HOST, // 主机数
        LICENSE_TYPE_SNAPSHOT, // 快照数
        LICENSE_TYPE_DATABASE, // 数据库
        LICENSE_TYPE_NET, // 网启数
        LICENSE_TYPE_VM, // 虚拟机数
        LICENSE_TYPE_FC, // 光纤卡数
        LICENSE_TYPE_CDP, // CDP个数
        LICENSE_TYPE_CDP_KEEPTIME, // CDP连续快照时间
        LICENSE_TYPE_CDP_KEEPUNIT, // CDP连续快照时间单位
        LICENSE_TYPE_EA_NUMBER, // 自动应急个数
        LICENSE_TYPE_EXPIRED_DATE, // 许可到期日
        LICENSE_TYPE_CREATE_TIME, // 许可创建时间
    };

    // 授权模式
    enum LicenseMode
    {
        LICENSE_MODE_HOST, // 基本
        LICENSE_MODE_EMERGENCY, // 应急
        LICENSE_MODE_CDP, // CDP
        LICENSE_MODE_EA, // 自动应急
        LICENSE_MODE_TIME, // 时间
    };

    // 解密类型
    enum BesDecryptType
    {
        BES_DECRYPT_TYPE_LICENSE,
        BES_DECRYPT_TYPE_FILE,
    };

public:

    /*
     *  功能：
     *      获取磁盘大小
     *  参数：
     *      无
     *  返回：
     *      磁盘大小
     */
    static string DiskSize();

    /*
     *  功能：
     *      获取磁盘序列号
     *  参数：
     *      无
     *  返回：
     *      磁盘序列号
     */
    static string DiskSerialNo();

    /*
     *  功能：
     *      生成License
     *  参数：
     *      host            :   主机数
     *      snapshot        :   快照数
     *      db              :   数据库数
     *      mode            :   授权模式
     *  返回：
     *      License
     */
    static string Encrypt(int host, int snapshot, int db, LicenseMode mode);

    /*
     *  功能：
     *      生成License
     *  参数：
     *      host            :   主机数
     *      snapshot        :   快照数
     *      db              :   数据库数
     *      filename        :   文件名
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *      mode            :   授权模式
     *  返回：
     *      License
     */
    static string Encrypt(int host, int snapshot, int db, string filename, string disksn, string disksize, LicenseMode mode);

    /*
     *  功能：
     *      生成License
     *  参数：
     *      expireddate     :   到期日
     *      filename        :   文件名
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *  返回：
     *      License
     */
    static string Encrypt(string expireddate, string filename, string disksn, string disksize);

    /*
     *  功能：
     *      生成License
     *  参数：
     *      input           :   到期日
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *      mode            :   模式
     *  返回：
     *      License
     */
    static string Encrypt(string input, string filename, string disksn, string disksize, LicenseMode mode);

    /*
     *  功能：
     *      解密License
     *  参数：
     *      instr           :   输入
     *      type            :   输入类型
     *      outlic          :   license号
     *      output          :   解密输出
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *      mode            :   授权模式
     *  返回：
     *      解密成功返回true，否则返回false
     */
    static bool Decrypt(string instr, BesEncryptF::BesDecryptType type, string& outlic, string &output, string disksn, string disksize, LicenseMode mode);


    /*
     *  功能：
     *      读取授权值
     *  参数
     *      type            :   授权类型
     *  返回：
     *      授权值
     */
    static string GetLicense(BesEncryptF::LicenseType type);

    /*
     *  功能：
     *      读取License
     *  参数
     *      type            :   License类型
     *      outlic          :   许可证号
     *  返回：
     *      授权值
     */
    static string GetLicense(BesEncryptF::LicenseType type, string &outlic);

    /*
     *  功能：
     *      读取License
     *  参数
     *      input           :   输入
     *      type            :   授权类型
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *      outlic          :   许可证号
     *  返回：
     *      授权值
     */
    static string GetLicense(string input, BesEncryptF::LicenseType type, string disksn, string disksize, string &outlic);

    /*
     *  功能：
     *      License文件是否存在
     */
    static bool IsLicenseExist();


    /*
     *  功能：
     *      获取License文件名
     *  参数
     *      path            :   License文件目录
     *  返回：
     *      License文件名
     */
    static string GetLicenseFile(string path);

public:
#define DEF_LICENSE_EXTENSION   ".lic"          // 默认License文件扩展名
#define DEF_LICENSE_NAME        "bes.lic"       // 默认License文件名

private:
#define DEF_BUFFER_SIZE         32              // 默认缓冲大小
#define DEF_ENCRYPT_BYTE_SIZE   16              // 默认加密字节长度
#define DEF_ENCRYPT_BMP         "bes.bmp"       // 默认加密位图文件名
private:

    enum TimeFormat
    {
        TIME_FORMAT_LONG, // %Y-%m-%d %H:%M:%S
        TIME_FORMAT_DATE, // %Y-%m-%d
        TIME_FORMAT_TIME, // %H:%M:%S
        TIME_FORMAT_FULL_DATETIME, // %Y%m%d%H%M%S
        TIME_FORMAT_FULL_DATE, // %Y%m%d
        TIME_FORMAT_FULL_TIME, // %H%M%S
        TIME_FORMAT_YEAR, //
        TIME_FORMAT_MONTH, //
        TIME_FORMAT_DAY,
        TIME_FORMAT_HOUR,
        TIME_FORMAT_MINUTE,
        TIME_FORMAT_SECOND,
        TIME_FORMAT_COMMAND_HEADER, // %d%H%M%S
    };
private:

    /*
     *  功能：
     *      获取初始化向量和密钥
     *  参数：
     *      disksn          :   磁盘序列号
     *      disksize        :   磁盘大小
     *      mode            :   许可方式
     *      iv              :   初始化向量
     *      key             :   加密密钥
     *  返回：
     *      加密后的字符串
     */
    static bool GetIvAndKey(string disksn, string disksize, LicenseMode mode, string &iv, string & key);

    /*
     *  功能：
     *      通用加/解密
     *  参数：
     *      iv              :   初始化向量
     *      key             :   加密密钥
     *      input           :   输入
     *      isencrypt       :   ture表示加密，否则表示解密
     *  返回：
     *      加/解密后的字符串(十六进制或原字符串）
     */
    static string GeneralEncrypt(string iv, string key, string input, bool isencrypt);

    /*
     *  功能：
     *      通用加/解密
     *  参数：
     *      iv              :   初始化向量
     *      key             :   加密密钥
     *      input           :   输入
     *      output          :   输出
     *      isencrypt       :   ture表示加密，否则表示解密
     *  返回：
     *      成功返回true，否则返回false
     */
    static bool GeneralEncrypt(string iv, string key, string input, string & output, bool isencrypt);

    /*
     *  功能：
     *      通用加/解密
     *  参数：
     *      iv              :   初始化向量
     *      key             :   加密密钥
     *      input           :   输入
     *      output          :   输出
     *      inputlen        :   输入长度
     *      outputlen       :   输出长度
     *      isencrypt       :   ture表示加密，否则表示解密
     *  返回：
     *      成功返回true，否则返回false
     */
    static bool GeneralEncrypt(const unsigned char *iv, const unsigned char * key, const unsigned char * input, unsigned char *output, int inputlen, int *outputlen, bool isencrypt);

    /*
     *  功能：
     *      MD5加密
     *  参数：
     *      instr           :   输入
     *  返回：
     *      加密后的字符串
     */
    static string MD5Encrypt(string instr);

    /*
     *  功能：
     *      初始化加密数组
     *  参数：
     *      arr             :   待初始化的数组
     *      mode            :   授权模式
     *  返回：
     *      加密数组长度
     */
    static int InitEncryptArray(int arr[], LicenseMode mode);

    /*
     *  功能：
     *      获取启动设备
     *  参数：
     *      无
     *  返回：
     *      启动设备名
     */
    static string GetBootDevice();

    /*
     *  功能：
     *      写license文件
     *  参数：
     *      filename        :   文件名
     *      license         :   license
     *      mode            :   授权模式
     *  返回：
     *      写入成功返回true，否则返回false
     */
    static bool WriteLicenseFile(string filename, string license, LicenseMode mode);

    /*
     *  功能：
     *      读取license文件
     *  参数：
     *      filename        :   文件名
     *      mode            :   授权模式
     *  返回：
     *      读取成功返回license，否则返回空
     */
    static string ReadLicenseFile(string filename, LicenseMode mode);

    /*
     *  功能：
     *      解析明文中的授权值
     *  参数：
     *      input           :   输入
     *      type            :   授权类型
     *  返回：
     *      对应的授权值
     */
    static string ParsePlainText(string input, LicenseType type);

    /*
     *  功能：
     *      解析明文中的授权值
     *  参数：
     *      input           :   输入
     *  返回：
     *      授权值列表
     */
    static vector<string> ParsePlainText(string input);

    /*
     *  功能：
     *      根据授权类型获取授权模式
     *  参数：
     *      type            :   授权类型
     *  返回：
     *      授权模式
     */
    static BesEncryptF::LicenseMode GetLicenseModeWithType(LicenseType type);

    /*
     *  功能：
     *      数字转换为字符串
     *  参数：
     *      num             :   数字
     *  返回：
     *      转换后的字符串形式
     */
    static string Number2String(long num);

    //    /*
    //     *  功能：
    //     *      数字转换为字符串
    //     *  参数：
    //     *      num             :   数字
    //     *  返回：
    //     *      转换后的字符串形式
    //     */
    //    static string Number2String(float num);

    /*
     *  功能：
     *      数字转换为字符串
     *  参数：
     *      num             :   数字
     *      precision       :   精度
     *  返回：
     *      转换后的字符串形式
     */
    static string Number2String(float num, int precision);

    /*
     *  功能：
     *      字符转换为字符串
     *  参数：
     *      c               :   字符
     *  返回：
     *      转换后的字符串
     */
    static string Char2String(char c);

    /*
     *  功能：
     *      字符串转换为整数
     *  参数：
     *      str             :   字符串
     *  返回：
     *      转换后的整数
     */
    static int StringToInt(string str);

    /*
     *  功能：
     *      字符串转换为浮点数
     *  参数：
     *      str             :   字符串
     *  返回：
     *      转换后的浮点数
     */
    static float StringToFloat(string str);

    /*
     *  功能：
     *      字符串转换为bool
     *  参数：
     *      str             :   字符串
     *  返回：
     *      转换后的bool值
     */
    static bool StringToBool(string str);

    /*
     *  功能：
     *      字符串转为大写
     *  参数
     *      str             :   输入字符串
     *  返回：
     *      命令字符串
     */
    static string StringToUpper(string str);

    /*
     *  功能：
     *      检查字段值是否为空或无效值
     *  参数
     *      str             :   要操作的字符串
     *  返回：
     *      如果是返回true，否则返回false
     */
    static bool IsStringEmptyOrInvalidValue(string str);

    /*  功能：
     *      检查字段值是否为空或无效值
     *  参数
     *      str             :   要操作的字符串
     *  返回：
     *      如果是返回true，否则返回false
     */
    static bool IsStringEmptyOrZero(string str);

    /*
     *  功能：
     *      检查字段值是否为空
     *  参数
     *      str             :   要操作的字符串
     *  返回：
     *      如果是返回true，否则返回false
     */
    static bool IsStringEmpty(string str);

    /*
     *  功能：
     *      执行系统命令
     *  参数
     *      shellcommand    :   执行命令串
     *      redirect        :   重定向
     *      msgtype         :   信息类型
     *  返回：
     *      成功返回true，否则返回false
     */
    static bool ExecuteSystem(string shellcommand, bool redirect = true);

    /*
     *  功能：
     *      读取shell返回值
     *  参数
     *      shellcommand    :   shell命令
     *  返回：
     *      shell返回值
     */
    static string ReadShellReturnValue(string shellcommand);

    /*
     *  功能：
     *      读取shell返回值
     *  参数
     *      shellcommand    :   shell命令
     *      tolog           :   输出到日志
     *  返回：
     *      shell返回值
     */
    static string ReadShellReturnValue(string shellcommand, bool tolog);

    /*
     *  功能：
     *      读取shell所有返回值
     *  参数
     *      shellcommand    :   shell命令
     *  返回：
     *      shell返回值
     */
    static vector<string> ReadShellReturnValueAll(string shellcommand);

    /*
     *  功能：
     *      读取shell所有返回值
     *  参数
     *      shellcommand    :   shell命令
     *      tolog           :   输出到日志
     *  返回：
     *      shell返回值
     */
    static vector<string> ReadShellReturnValueAll(string shellcommand, bool tolog);

    /*
     *  功能：
     *      获取执行路径名
     *  参数：
     *      无
     *  返回：
     *      执行路径名
     */
    static string GetExecutePath();

    /*
     *  功能：
     *      文件是否存在
     *  参数：
     *      file            :   文件名
     *  返回：
     *      如果存在返回true，否则返回false
     */
    static bool IsFileExist(string file);

    /*
     *  功能：
     *      移动文件
     *  参数：
     *      source          :   源文件名
     *      dest            :   目标文件名
     *      overwrite       :   是否覆盖
     *  返回：
     *      操作成功返回true,否则返回false
     */
    static bool CopyFile(string source, string dest, bool overwrite, bool debug = true);

    /*
     *  功能：
     *      十六进制转换为十进制
     *  参数：
     *      str             :   十六进制字符串
     *  返回：
     *      转换后的十进制数
     */
    static int HexToDecimal(string str);

    /*
     *  功能：
     *      将数组转换为十六进制字符串
     *  参数：
     *      arr             :   数组
     *      len             :   数组长度
     *  返回：
     *      转换后的十六进制字符串
     */
    static string ArrayToHexString(unsigned char *arr, int len);

    /*
     *  功能：
     *      将字节转换为十六进制字符串
     *  参数：
     *      byte            :   字节
     *      isupper         :   是否大写
     *  返回：
     *      转换后的十六进制字符串
     */
    static string ByteToHexString(unsigned char ch, bool isupper);

    /*
     *  功能：
     *      获取当前时间格式
     *  参数：
     *      format          :   时间格式
     *  返回：
     *      时间字符串
     */
    static string GetTimeString(BesEncryptF::TimeFormat format);

    /*
     *  功能：
     *      获取当前时间格式
     *  参数：
     *      time            :   时间
     *      format          :   时间格式
     *  返回：
     *      时间字符串
     */
    static string GetTimeString(time_t time, BesEncryptF::TimeFormat format);

    /*
     *  功能：
     *      获取当前时间格式
     *  参数：
     *      tmptr           :   时间结构指针
     *      format          :   时间格式
     *  返回：
     *      时间字符串
     */
    static string GetTimeString(struct tm *tmptr, BesEncryptF::TimeFormat format);

    /*
     *  功能：
     *      获取日期格式字符串
     *  参数
     *      format          :   日期格式
     *  返回：
     *      日期格式字符串
     */
    static string GetTimeFormatString(BesEncryptF::TimeFormat format);

    /*
     *  功能：
     *      打印调试信息
     *  参数：
     *      msg             :   文件名
     *  返回：
     *      无
     */
    static void DebugPrint(string msg);

};

#endif	/* _BESENCRYPTF_H */

