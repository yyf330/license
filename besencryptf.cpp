#include "besencryptf.h"

/*
 *  功能：
 *      构造函数
 *  参数：
 *      无
 *  返回：
 *      无
 */
BesEncryptF::BesEncryptF()
{
}

/*
 *  功能：
 *      析构函数
 *  参数：
 *     无
 *  返回：
 *      无
 */
BesEncryptF::~BesEncryptF()
{
}

//---------------------------------- 公有方法 ----------------------------------//

/*
 *  功能：
 *      获取磁盘大小
 *  参数：
 *      无
 *  返回：
 *      磁盘大小
 */
string BesEncryptF::DiskSize()
{
    // 获取启动盘
    string Device = GetBootDevice();
    if (IsStringEmpty(Device) == true)
    {
        cout << "Boot device is empty!" << endl;
        return DEFAULT_EMPTY_STRING;
    }

    // 获取对应的磁盘大小
    string ShellCommand = string("fdisk -s") + SEPARATOR_CHAR_SPACE + Device;
    string Size = ReadShellReturnValue(ShellCommand);
    return Size;

}

/*
 *  功能：
 *      获取磁盘序列号
 *  参数：
 *      无
 *  返回：
 *      磁盘序列号
 */
string BesEncryptF::DiskSerialNo()
{
    // 获取启动盘
    string Device = GetBootDevice();
    if (IsStringEmpty(Device) == true)
    {
        cout << "Boot device is empty!" << endl;
        return DEFAULT_EMPTY_STRING;
    }

    // 获取磁盘序列号
    string Disk = Device;
    string LastSubStr = Disk.substr(Device.size() - 1, 1);
    if (StringToInt(LastSubStr) != 0)
    {
        Disk = Device.substr(0, Device.size() - 1);
    }
    string ShellCommand = string("hdparm -i ") + SEPARATOR_CHAR_SPACE + Disk + SEPARATOR_CHAR_SPACE + string(" 2>/dev/null | gawk '/SerialNo/ {split($0, SArr, \"=\")} END{print SArr[4]}'|gawk '{print $1}'");
    string SerialNo = ReadShellReturnValue(ShellCommand);
    if (IsStringEmpty(SerialNo) == true) // 系统盘不是固态盘，而是raid分区
    {
        ShellCommand = string("blkid -o export ") + SEPARATOR_CHAR_SPACE + Device + SEPARATOR_CHAR_SPACE + string(" | grep ^UUID | gawk -F= '{print $2}'");
        SerialNo = ReadShellReturnValue(ShellCommand);
    }

    if (IsStringEmpty(SerialNo) == true) // 系统盘不是固态盘和raid分区，而是卷
    {
        ShellCommand = string("lvname=$(echo ") + SEPARATOR_CHAR_SPACE + Device + SEPARATOR_CHAR_SPACE + string(" | gawk -F/ '{print $NF}' | gawk -F- '{print $NF}') && lvs -o lv_name,lv_uuid 2>/dev/null | gawk '{if($1==\"'$lvname'\") print $2}'");
        SerialNo = ReadShellReturnValue(ShellCommand);
    }
    return SerialNo;
}

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
string BesEncryptF::Encrypt(int host, int snapshot, int db, LicenseMode mode)
{
    return Encrypt(host, snapshot, db, "", DiskSerialNo(), DiskSize(), mode);
}

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
string BesEncryptF::Encrypt(int host, int snapshot, int db, string filename, string disksn, string disksize, LicenseMode mode)
{

    // 主机数
    string HostNum = Number2String(host);
    string HostNumSize = Number2String(HostNum.size());

    // 快照数
    string SnapshotNum = Number2String(snapshot);
    string SnapshotNumSize = Number2String(SnapshotNum.size());

    // 数据库数
    string DbNum = Number2String(db);
    string DbNumSize = Number2String(DbNum.size());

    // 输入值
    string Input = HostNumSize + HostNum + SnapshotNumSize + SnapshotNum + DbNumSize + DbNum;
    return Encrypt(Input, filename, disksn, disksize, mode);
}

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
string BesEncryptF::Encrypt(string expireddate, string filename, string disksn, string disksize)
{
    // 加密输入值
    string Input = expireddate + GetTimeString(TIME_FORMAT_FULL_DATETIME);
    return Encrypt(Input, filename, disksn, disksize, LICENSE_MODE_TIME);
}

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
string BesEncryptF::Encrypt(string input, string filename, string disksn, string disksize, LicenseMode mode)
{
    string Iv = "";
    string Key = "";

    // 获取初始化向量和密钥
    GetIvAndKey(disksn, disksize, mode, Iv, Key);

    // 进行加密
    string LicenseString = GeneralEncrypt(Iv, Key, input, true);

    // 如果成功则写入授权文件中
    if (LicenseString.empty() == false && filename.empty() == false)
    {
        WriteLicenseFile(filename, LicenseString, mode);
    }
    return LicenseString;
}

/*
 *  功能：
 *      读取License
 *  参数
 *      type            :   License类型
 *  返回：
 *      License个数
 */
string BesEncryptF::GetLicense(BesEncryptF::LicenseType type)
{
    string OutLicense = "";
    return GetLicense(type, OutLicense);
}

/*
 *  功能：
 *      读取License
 *  参数
 *      type            :   License类型
 *  返回：
 *      License个数
 */
string BesEncryptF::GetLicense(BesEncryptF::LicenseType type, string & outlic)
{
    return GetLicense(GetLicenseFile(GetExecutePath()), type, DiskSerialNo(), DiskSize(), outlic);
}

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
string BesEncryptF::GetLicense(string input, BesEncryptF::LicenseType type, string disksn, string disksize, string & outlic)
{
    string Output = "";
    if (Decrypt(input, (IsFileExist(input) == true) ? BesEncryptF::BES_DECRYPT_TYPE_FILE : BesEncryptF::BES_DECRYPT_TYPE_LICENSE, outlic, Output, disksn, disksize, GetLicenseModeWithType(type)) == false)
    {
        return "";
    }

    return ParsePlainText(Output, type);
}

/*
 *  功能：
 *      License文件是否存在
 *  参数
 *      path            :   License文件目录
 */
bool BesEncryptF::IsLicenseExist()
{
    return (IsFileExist(GetLicenseFile(GetExecutePath())) == true);
}

/*
 *  功能：
 *      获取License文件名
 *  参数
 *      path            :   License文件目录
 *  返回：
 *      License文件名
 */
string BesEncryptF::GetLicenseFile(string path)
{
    // 列举License文件
    string ShellCommand = string("ls") + SEPARATOR_CHAR_SPACE + path + SEPARATOR_CHAR_SPACE + string(" | grep ") + DEF_LICENSE_EXTENSION + string("$");

    // 获取License文件列表
    vector<string> LicFileList = ReadShellReturnValueAll(ShellCommand);

    string LicenseFile = "";
    for (int i = 0; i < LicFileList.size(); i++)
    {
        if (LicFileList[i] != DEF_LICENSE_NAME)
        {
            LicenseFile = LicFileList[i];
        }
    }
    if (LicenseFile == "")
    {
        LicenseFile = DEF_LICENSE_NAME;
    }
    LicenseFile = path + LicenseFile;
    return LicenseFile;
}

//---------------------------------- 私有方法 ----------------------------------//

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
bool BesEncryptF::Decrypt(string instr, BesEncryptF::BesDecryptType type, string & outlic, string &output, string disksn, string disksize, LicenseMode mode)
{
    string License = "";
    output = "";
    outlic = "";
    switch (type)
    {
        case BesEncryptF::BES_DECRYPT_TYPE_LICENSE:
        {
            License = instr;
            break;
        }
        case BesEncryptF::BES_DECRYPT_TYPE_FILE:
        {
            License = ReadLicenseFile(instr, mode);
            break;
        }
        default:
        {
            return false;
        }
    }
    outlic = License;
    if (License == "")
    {
        return false;
    }
    string Iv = "";
    string Key = "";
    GetIvAndKey(disksn, disksize, mode, Iv, Key);
    string Output = GeneralEncrypt(Iv, Key, License, false);
    if (Output == "")
    {
        return false;
    }
    output = Output;
    return true;
}

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
bool BesEncryptF::GetIvAndKey(string disksn, string disksize, LicenseMode mode, string &iv, string & key)
{
    // 检查输入有效性
    if (disksn.empty() == true || disksize.empty() == true)
    {
        return false;
    }

    string SnMD5 = MD5Encrypt(disksn);
    string SpaceMD5 = MD5Encrypt(disksize);
    string Iv = SpaceMD5.substr(0, 16);
    string Key = SnMD5.substr(15, 16);
    switch (mode)
    {
        case BesEncryptF::LICENSE_MODE_EMERGENCY:
        {
            Iv = SnMD5.substr(0, 16);
            Key = SpaceMD5.substr(15, 16);
            break;
        }
        case BesEncryptF::LICENSE_MODE_CDP:
        {
            Iv = SnMD5.substr(4, 16);
            Key = SpaceMD5.substr(8, 16);
            break;
        }
        case BesEncryptF::LICENSE_MODE_EA:
        {
            Iv = SpaceMD5.substr(4, 16);
            Key = SnMD5.substr(8, 16);
            break;
        }
        case BesEncryptF::LICENSE_MODE_TIME:
        {
            Iv = SpaceMD5.substr(6, 16);
            Key = SnMD5.substr(10, 16);
            break;
        }
    }
    iv = Iv;
    key = Key;

    //    cout << "DiskSn:" << disksn << "\tmd5:" << SnMD5 << endl;
    //    cout << "DiskSize:" << disksize << "\tmd5:" << SpaceMD5 << endl;
    //    cout << "Iv:" << Iv << endl;
    //    cout << "Key:" << Key << endl;
    return true;
}

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
string BesEncryptF::GeneralEncrypt(string iv, string key, string input, bool isencrypt)
{
    string output = "";
    GeneralEncrypt(key, iv, input, output, isencrypt);
    return output;
}

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
bool BesEncryptF::GeneralEncrypt(string iv, string key, string input, string & output, bool isencrypt)
{
    int InputSize = input.size();
    unsigned char OutBuffer[InputSize + EVP_MAX_KEY_LENGTH];
    unsigned char InBuffer[InputSize + EVP_MAX_KEY_LENGTH];
    int outlen = 0;
    //    cout << "E0" << endl;
    //    cout << "iv:" << iv << endl;
    //    cout << "Key:" << key << endl;
    //    cout << "Input:" << input << endl;

    // 清零缓冲
    bzero(OutBuffer, sizeof (OutBuffer));
    bzero(InBuffer, sizeof (InBuffer));

    // 对输入数据进行处理
    if (isencrypt == false)
    {
        for (int i = 0; i < InputSize / 2; i++)
        {
            InBuffer[i] = (unsigned char) HexToDecimal(input.substr(i * 2, 2));
        }
        InputSize = InputSize / 2;
    }
    else
    {
        for (int i = 0; i < InputSize; i++)
        {
            InBuffer[i] = input.c_str()[i];
        }
    }

    // 加/解密
    if (GeneralEncrypt((const unsigned char *) key.c_str(), (const unsigned char *) iv.c_str(), (const unsigned char *) InBuffer, OutBuffer, InputSize, &outlen, isencrypt) == false)
    {
        return false;
    }


    char MsgBuf[3];
    bzero(MsgBuf, sizeof (MsgBuf));

    string Str = "";
    int i = 0;
    while (i < outlen)
    {
        if (isencrypt == true)
        {
            sprintf(MsgBuf, "%02X\0", OutBuffer[i++]);
        }
        else
        {
            sprintf(MsgBuf, "%c\0", OutBuffer[i++]);
        }
        Str += MsgBuf;
    }
    output = Str;
    return true;
}

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
bool BesEncryptF::GeneralEncrypt(const unsigned char *iv, const unsigned char * key, const unsigned char * input, unsigned char *output, int inputlen, int *outputlen, bool isencrypt)
{
    int OutLength1 = 0; //第一次使用update加密的数据长度
    int OutLength2 = 0; //剩余的字段，经过final填充后的长度
    int ReturnValue = 0;
    EVP_CIPHER_CTX ctx;

    //    printf("Input:");
    //    disp(in_enc, in_len);
    //    printf("in_len=%d\n", in_len);
    //
    //    printf("key:");
    //    disp(key, strlen((const char *) key));
    //    printf("iv:");
    //    disp(iv, strlen((const char *) iv));

    //初始化ctx
    EVP_CIPHER_CTX_init(&ctx);

    ReturnValue = (isencrypt == true) ? EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv) : EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv); //设置密码算法、key和iv
    if (ReturnValue != 1)
    {
        //        perror("init err");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return false;
    }

    ReturnValue = (isencrypt == true) ? EVP_EncryptUpdate(&ctx, output, &OutLength1, input, inputlen) : EVP_DecryptUpdate(&ctx, output, &OutLength1, input, inputlen); //加密
    if (ReturnValue != 1)
    {

        //        perror("update error");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return false;
    }

    //加密结束
    ReturnValue = (isencrypt == true) ? EVP_EncryptFinal_ex(&ctx, output + OutLength1, &OutLength2) : EVP_DecryptFinal_ex(&ctx, output + OutLength1, &OutLength2);
    if (ReturnValue != 1)
    {
        //        perror("final error");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return false;
    }

    *outputlen = OutLength1 + OutLength2;
    EVP_CIPHER_CTX_cleanup(&ctx); //清除EVP加密上下文环境


    //    printf("output:");
    //    disp(out_enc, *out_len);

    return true;
}

/*
 *  功能：
 *      MD5加密
 *  参数：
 *      instr           :   输入
 *  返回：
 *      加密后的字符串
 */
string BesEncryptF::MD5Encrypt(string instr)
{
    const EVP_MD *md5 = EVP_md5();

    EVP_MD_CTX Ctx;

    EVP_DigestInit(&Ctx, md5);

    unsigned char OutBuffer[DEF_ENCRYPT_BYTE_SIZE];
    unsigned int OutLen = 0;

    if (!EVP_DigestUpdate(&Ctx, instr.c_str(), instr.size()))
    {
        return "";
    }

    if (!EVP_DigestFinal(&Ctx, OutBuffer, &OutLen))
    {
        return "";
    }

    return (ArrayToHexString(OutBuffer, OutLen));
}

/*
 *  功能：
 *      初始化加密数组
 *  参数：
 *      arr             :   待初始化的数组
 *  返回：
 *      加密数组长度
 */
int BesEncryptF::InitEncryptArray(int arr[], LicenseMode mode)
{
    int Offet[] = {0x4567, 0x5674, 0x6745, 0x7456,
        0xcdef, 0xdefc, 0xefcd, 0xfcde,
        0x10123, 0x11230, 0x12301, 0x3012,
        0x189ab, 0x19ab8, 0x1ab89, 0x1b89a};

    int Offet2[] = {0x48b3, 0x69e1, 0x8df4, 0xa1a6,
        0xb137, 0xbcab, 0xc3f4, 0xcaaa,
        0x687, 0xffe, 0x1718, 0x2bcd,
        0x3214, 0x37ef, 0x3c81, 0x3eee};


    int Offet3[] = {0x12a7, 0x2145, 0x29af, 0x4bda,
        0x5d41, 0x6022, 0x68e9, 0x71af,
        0x7e90, 0x83c2, 0x9154, 0x95ff,
        0xa20c, 0xa799, 0xb2b2, 0xb985};

    int Offet4[] = {0x55a, 0x1134, 0x15fe, 0x22dd,
        0x28a5, 0x3030, 0x3adf, 0x43ea,
        0x63f1, 0x6c55, 0x791f, 0x82ad,
        0x9296, 0xa543, 0xc69e, 0x577};

    int Offet5[] = {0x58d7, 0x96a, 0x18ef, 0x261c,
        0x327e, 0x3be5, 0x170, 0x6bc1,
        0x85a2, 0x9206, 0xc2b4, 0x9f49,
        0xaaf8, 0xaf13, 0xb5ed, 0x98ff,
        0x85a1, 0x117f, 0x191b, 0x6ebc,
        0x1ba7, 0x98f6, 0x258d, 0x2b15,
        0x3289, 0x36e0, 0x41a2, 0x8ea,
        0xe23, 0x78e4, 0x4618, 0x214e};

    int ArraySize = 16;
    switch (mode)
    {
        case BesEncryptF::LICENSE_MODE_HOST:
        {
            for (int i = 0; i < ArraySize; i++)
            {
                arr[i] = Offet[i];
            }
            break;
        }
        case BesEncryptF::LICENSE_MODE_EMERGENCY:
        {
            for (int i = 0; i < ArraySize; i++)
            {
                arr[i] = Offet2[i];
            }
            break;
        }
        case BesEncryptF::LICENSE_MODE_CDP:
        {
            for (int i = 0; i < ArraySize; i++)
            {
                arr[i] = Offet3[i];
            }
            break;
        }
        case BesEncryptF::LICENSE_MODE_EA:
        {
            for (int i = 0; i < ArraySize; i++)
            {
                arr[i] = Offet4[i];
            }
            break;
        }
        case BesEncryptF::LICENSE_MODE_TIME:
        {
            ArraySize = 32;
            for (int i = 0; i < ArraySize; i++)
            {
                arr[i] = Offet5[i];
            }
            break;
        }
        default:
        {
            ArraySize = 0;
            break;
        }
    }
    return ArraySize;
}

/*
 *  功能：
 *      获取启动设备
 *  参数：
 *      无
 *  返回：
 *      启动设备名
 */
string BesEncryptF::GetBootDevice()
{
    string Device = "";

    // 获取对应的设备
    string GrubConfigFile = string("/boot/grub/grub.conf");
    if (IsFileExist(GrubConfigFile) == false)
    {
        GrubConfigFile = string("/boot/efi/EFI/redhat/grub.conf");
    }

    if (IsFileExist(GrubConfigFile) == true)
    {
        string ShellCommand = string("mountpoint=$(label=$(cat ") + SEPARATOR_CHAR_SPACE + GrubConfigFile + SEPARATOR_CHAR_SPACE + string(" | grep root= | grep -v '#' | grep -v 'module' | gawk '{print $4}' | gawk -Froot= '{print $2}' | sort -u | gawk '{if(NR==1) print $0}')  && cat /etc/fstab |  gawk '{if($1==\"'$label'\") print $2}') && df -Plh 2>/dev/null | gawk '{if($6==\"'$mountpoint'\") print $1}'");
        Device = ReadShellReturnValue(ShellCommand);
        if (IsStringEmpty(Device) == true)
        {
            ShellCommand = string("mountpoint=$(label=$(cat ") + SEPARATOR_CHAR_SPACE + GrubConfigFile + SEPARATOR_CHAR_SPACE + string(" | grep root= | grep -v '#' | grep -v 'kernel' | gawk '{print $4}' | gawk -Froot= '{print $2}' | sort -u | gawk '{if(NR==1) print $0}')  && cat /etc/fstab |  gawk '{if($1==\"'$label'\") print $2}') && df -Plh 2>/dev/null | gawk '{if($6==\"'$mountpoint'\") print $1}'");
            Device = ReadShellReturnValue(ShellCommand);
        }

        if (IsStringEmpty(Device) == true)
        {
            ShellCommand = string("mountpoint=$(label=$(cat ") + SEPARATOR_CHAR_SPACE + GrubConfigFile + SEPARATOR_CHAR_SPACE + string(" | grep root= | grep -v '#' | grep -v 'module' | gawk '{print $3}' | gawk -Froot= '{print $2}' | sort -u | gawk '{if(NR==1) print $0}')  && cat /etc/fstab |  gawk '{if($1==\"'$label'\") print $2}') && df -Plh 2>/dev/null | gawk '{if($6==\"'$mountpoint'\") print $1}'");
            Device = ReadShellReturnValue(ShellCommand);
        }
    }
    else
    {
        GrubConfigFile = string("/boot/grub/grub.cfg");
        string ShellCommand = string("lsblk -p -l | gawk '{if($7==\"/\") print $1}'");
        Device = ReadShellReturnValue(ShellCommand);
    }

    // 检查设备是否为空
    if (IsStringEmpty(Device) == true)
    {
        string BootConfigFile = string("/etc/yaboot.conf");

        // 如果配置文件存在
        if (IsFileExist(BootConfigFile) == true)
        {
            string ShellCommand = string("cat") + SEPARATOR_CHAR_SPACE + BootConfigFile + string("| sed -n '/`uname -r`/{:a;n;/image/q;p;ba}' |  gawk -F= '{if($1~\"root\") print $2}'");
            Device = ReadShellReturnValue(ShellCommand);

            // 如果设备为空
            if (IsStringEmpty(Device) == true)
            {
                string ShellCommand = string("cat") + SEPARATOR_CHAR_SPACE + BootConfigFile + string("| gawk -F= '{if($1~\"root\") print $2}'");
                Device = ReadShellReturnValue(ShellCommand);
            }
        }
    }
    return Device;
}

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
bool BesEncryptF::WriteLicenseFile(string filename, string license, LicenseMode mode)
{
    // 检测文件是否为空
    if (IsStringEmptyOrInvalidValue(filename) == true)
    {
        DebugPrint("The file name is null or empty!");
        return false;
    }

    // 加密生成License号
    if (license == "")
    {
        DebugPrint("The license number is empty!");
        return false;
    }

    // 添加默认扩展名
    if (filename.size() < strlen(DEF_LICENSE_EXTENSION) || filename.substr(filename.size() - 4, 4) != DEF_LICENSE_EXTENSION)
    {
        filename += DEF_LICENSE_EXTENSION;
    }


    // 生成License文件
    if (IsFileExist(filename) == false)
    {
        // 检测加密的图像文件是否存在
        if (IsFileExist(DEF_ENCRYPT_BMP) == false)
        {
            return false;
        }

        CopyFile(DEF_ENCRYPT_BMP, filename, true, false);
    }

    // 写入位图载体
    FILE *fp;
    fp = fopen(filename.c_str(), "rb+");
    if (fp == NULL)
    {
        return false;
    }
    int Offset[32];
    bzero(Offset, sizeof (Offset));
    int ArraySize = InitEncryptArray(Offset, mode);
    for (int i = 0; i < ArraySize; i++)
    {
        unsigned char ch = (unsigned char) HexToDecimal(license.substr(i * 2, 2));
        fseek(fp, Offset[i], SEEK_SET);
        fwrite(&ch, 1, 1, fp);
    }
    fclose(fp);

    return true;
}

/*
 *  功能：
 *      读取license文件
 *  参数：
 *      filename        :   文件名
 *      mode            :   授权模式
 *  返回：
 *      读取成功返回license，否则返回空
 */
string BesEncryptF::ReadLicenseFile(string filename, LicenseMode mode)
{
    string License = "";

    // 检查文件是否存在
    if (IsFileExist(filename) == false)
    {
        DebugPrint(string("The file <") + filename + "> does not exist!");
        return License;
    }

    FILE *fp;
    fp = fopen(filename.c_str(), "r");
    if (fp == NULL)
    {
        DebugPrint(string("Open file <") + filename + "> failed!");
        return "";
    }
    int Offset[32];
    bzero(Offset, sizeof (Offset));
    int ArraySize = InitEncryptArray(Offset, mode);
    for (int i = 0; i < ArraySize; i++)
    {
        unsigned char ch;
        fseek(fp, Offset[i], SEEK_SET);
        fread(&ch, 1, 1, fp);
        License += ByteToHexString(ch, true);
    }
    fclose(fp);

    return License;
}

/*
 *  功能：
 *      解析明文中的授权值
 *  参数：
 *      input           :   输入
 *      type            :   授权类型
 *  返回：
 *      对应的授权值
 */
string BesEncryptF::ParsePlainText(string input, LicenseType type)
{
    string LicenseValue = "";

    // 检查输入的有效性
    if (input.empty() == true)
    {
        return "";
    }

    if (type == LICENSE_TYPE_EXPIRED_DATE || type == LICENSE_TYPE_CREATE_TIME)
    {
        switch (type)
        {
            case LICENSE_TYPE_EXPIRED_DATE:
            {
                if (input.size() >= 8)
                {
                    LicenseValue = input.substr(0, 8);
                }
                break;
            }
            case LICENSE_TYPE_CREATE_TIME:
            {
                if (input.size() >= 22)
                {
                    LicenseValue = input.substr(8, 14);
                }
                break;
            }
        }
    }
    else
    {
        vector<string> LicenseValueList = ParsePlainText(input);
        int ArrayIndex = -1;
        switch (type)
        {
            case LICENSE_TYPE_HOST: // 主机数
            case LICENSE_TYPE_NET: // 网启数
            case LICENSE_TYPE_CDP: // cdp个数
            case LICENSE_TYPE_EA_NUMBER: // 自动应急数
            {
                ArrayIndex = 0;
                break;
            }
            case LICENSE_TYPE_SNAPSHOT: // 快照数
            case LICENSE_TYPE_VM: // 虚拟机数
            case LICENSE_TYPE_CDP_KEEPTIME: // cdp快照保留时间
            {
                ArrayIndex = 1;
                break;
            }
            case LICENSE_TYPE_DATABASE: // 数据库数
            case LICENSE_TYPE_FC: // 光纤数
            case LICENSE_TYPE_CDP_KEEPUNIT: // cdp快照保留时间单位
            {
                ArrayIndex = 2;
                break;
            }
            default:
            {
                break;
            }
        }
        if (LicenseValueList.size() >= ArrayIndex && ArrayIndex != -1)
        {
            LicenseValue = LicenseValueList[ArrayIndex];
        }
    }
    return LicenseValue;
}

/*
 *  功能：
 *      解析明文中的授权值
 *  参数：
 *      input           :   输入
 *  返回：
 *      授权值列表
 */
vector<string> BesEncryptF::ParsePlainText(string input)
{
    vector<string> ValueList;

    // 检查输入的有效性
    if (input.empty() == true)
    {
        return ValueList;
    }

    string Value = "";

    int Position = 0;
    while (true)
    {
        // 检查输入长度
        if (input.size() < Position + 1)
        {
            break;
        }

        // 获取值的长度
        int Length = StringToInt(input.substr(Position, 1));
        Position++;

        // 检查输入长度
        if (input.size() < Position + Length)
        {
            break;
        }

        // 获取值
        Value = input.substr(Position, Length);
        ValueList.push_back(Value);
        Position += Length;
    }

    return ValueList;

}

/*
 *  功能：
 *      根据授权类型获取授权模式
 *  参数：
 *      type            :   授权类型
 *  返回：
 *      授权模式
 */
BesEncryptF::LicenseMode BesEncryptF::GetLicenseModeWithType(LicenseType type)
{
    LicenseMode Mode = BesEncryptF::LICENSE_MODE_HOST;
    switch (type)
    {
        case LICENSE_TYPE_NET: // 网启数
        case LICENSE_TYPE_VM: // 虚拟机数
        case LICENSE_TYPE_FC: // 光纤数
        {
            Mode = BesEncryptF::LICENSE_MODE_EMERGENCY;
            break;
        }
        case LICENSE_TYPE_CDP: // CDP个数
        case LICENSE_TYPE_CDP_KEEPTIME: // CDP快照保留时间
        case LICENSE_TYPE_CDP_KEEPUNIT: // CDP快照保留时间单位
        {
            Mode = BesEncryptF::LICENSE_MODE_CDP;
            break;
        }
        case LICENSE_TYPE_EA_NUMBER: // 自动应急数
        {
            Mode = BesEncryptF::LICENSE_MODE_EA;
            break;
        }
        case LICENSE_TYPE_EXPIRED_DATE: // 许可到期日
        case LICENSE_TYPE_CREATE_TIME: // 许可创建时间
        {
            Mode = BesEncryptF::LICENSE_MODE_TIME;
            break;
        }
    }
    return Mode;
}

/*
 *  功能：
 *      数字转换为字符串
 *  参数：
 *      num             :   数字
 *  返回：
 *      转换后的字符串形式
 */
string BesEncryptF::Number2String(long num)
{
    char Buf[DEFAULT_BUFFER_SIZE + 1];
    bzero(Buf, sizeof (Buf));
    sprintf(Buf, "%ld\0", num);
    return string(Buf);
}

/*
 *  功能：
 *      数字转换为字符串
 *  参数：
 *      num             :   数字
 *      precision       :   精度
 *  返回：
 *      转换后的字符串形式
 */
string BesEncryptF::Number2String(float num, int precision)
{
    std::ostringstream OStringStream;
    if (precision <= 0)
    {
        OStringStream << num;
    }
    else
    {
        OStringStream << setprecision(precision) << num;
    }
    return OStringStream.str();
}

/*
 *  功能：
 *      字符转换为字符串
 *  参数：
 *      c               :   字符
 *  返回：
 *      转换后的字符串
 */
string BesEncryptF::Char2String(char c)
{
    string s = DEFAULT_EMPTY_STRING;
    s.push_back(c);
    return s;
}

/*
 *  功能：
 *      字符串转换为整数
 *  参数：
 *      str             :   字符串
 *  返回：
 *      转换后的整数
 */
int BesEncryptF::StringToInt(string str)
{
    return (atoi(str.c_str()));
}

/*
 *  功能：
 *      字符串转换为浮点数
 *  参数：
 *      str             :   字符串
 *  返回：
 *      转换后的浮点数
 */
float BesEncryptF::StringToFloat(string str)
{
    return (atof(str.c_str()));
}

/*
 *  功能：
 *      字符串转换为bool
 *  参数：
 *      str             :   字符串
 *  返回：
 *      转换后的bool值
 */
bool BesEncryptF::StringToBool(string str)
{
    return (bool)(StringToInt(str));
}

/*
 *  功能：
 *      字符串转为大写
 *  参数
 *      str         :   输入字符串
 *  返回：
 *      命令字符串
 */
string BesEncryptF::StringToUpper(string str)
{
    if (IsStringEmpty(str) == true)
    {
        return DEFAULT_EMPTY_STRING;
    }

    string ResultStr = DEFAULT_EMPTY_STRING;
    const char *StrPointer = str.c_str();
    for (int i = 0; i < str.size(); i++)
    {
        ResultStr += (char) toupper(StrPointer[i]);
    }
    return ResultStr;
}

/*
 *  功能：
 *      检查字段值是否为空或无效值
 *  参数
 *      str             :   要操作的字符串
 *  返回：
 *      如果是返回true，否则返回false
 */
bool BesEncryptF::IsStringEmptyOrInvalidValue(string str)
{
    return (str.empty() == true || str == DEFAULT_INVALID_RETURN_VALUE || str == DEFAULT_INVALID_RETURN_VALUE2);
}

/*
 *  功能：
 *      检查字段值是否为空或无效值
 *  参数
 *      str             :   要操作的字符串
 *  返回：
 *      如果是返回true，否则返回false
 */
bool BesEncryptF::IsStringEmptyOrZero(string str)
{
    return (IsStringEmpty(str) == true || str == "0");
}

/*
 *  功能：
 *      检查字段值是否为空或无效值
 *  参数
 *      str             :   要操作的字符串
 *  返回：
 *      如果是返回true，否则返回false
 */
bool BesEncryptF::IsStringEmpty(string str)
{
    return (str.empty() == true);
}

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
bool BesEncryptF::ExecuteSystem(string shellcommand, bool redirect)
{
    string CommandStr = shellcommand;

    // 重定向
    if (redirect == true)
    {
        CommandStr = CommandStr + SEPARATOR_CHAR_SPACE + string("&> /dev/null");
    }

    DebugPrint("ShellCommand:" + CommandStr);

    pid_t Status = system(CommandStr.c_str());

    bool Flag = false;
    if (-1 == Status)
    {
        Flag = false;
    }
    else
    {
        if (WIFEXITED(Status))
        {
            if (0 == WEXITSTATUS(Status))
            {
                Flag = true;
            }
            else
            {
                Flag = false;
            }
        }
        else
        {
            Flag = false;
        }
    }
    return Flag;
}

/*
 *  功能：
 *      读取shell返回值
 *  参数
 *      shellcommand    :   shell命令
 *  返回：
 *      shell返回值
 */
string BesEncryptF::ReadShellReturnValue(string shellcommand)
{
    return ReadShellReturnValue(shellcommand, true);
}

/*
 *  功能：
 *      读取shell返回值
 *  参数
 *      shellcommand    :   shell命令
 *      tolog           :   输出到日志
 *  返回：
 *      shell返回值
 */
string BesEncryptF::ReadShellReturnValue(string shellcommand, bool tolog)
{
    vector<string> ValueList = ReadShellReturnValueAll(shellcommand, tolog);
    if (ValueList.size() == 0)
    {
        return "";
    }
    return ValueList[0];
}

/*
 *  功能：
 *      读取shell所有返回值
 *  参数
 *      shellcommand    :   shell命令
 *  返回：
 *      shell返回值
 */
vector<string> BesEncryptF::ReadShellReturnValueAll(string shellcommand)
{
    return ReadShellReturnValueAll(shellcommand, true);
}

/*
 *  功能：
 *      读取shell所有返回值
 *  参数
 *      shellcommand    :   shell命令
 *  返回：
 *      shell返回值
 */
vector<string> BesEncryptF::ReadShellReturnValueAll(string shellcommand, bool tolog)
{
    vector<string> ValueList;
    FILE *fp;
    //    if (tolog == true)
    //    {
    //        BesLog::DebugPrint("ShellCommand:" + shellcommand, BesLog::LOG_MESSAGE_TYPE_NORMAL, true);
    //    }

    if ((fp = popen(shellcommand.c_str(), "r")) == NULL)
    {
        //        if (tolog == true)
        //        {
        //            BesLog::DebugPrint("Open shellcommand failed!\n", BesLog::LOG_MESSAGE_TYPE_NORMAL, true);
        //        }
        return ValueList;
    }
    char Buf[DEFAULT_BUFFER_SIZE + 1];
    while (!feof(fp))
    {
        bzero(Buf, sizeof (Buf));
        fgets(Buf, sizeof (Buf), fp);
        Buf[strlen(Buf) - 1] = DEFAULT_C_STRING_END_FLAG;
        if (IsStringEmpty(string(Buf)) == false)
        {
            ValueList.push_back(string(Buf));
        }
        //        else
        //        {
        //            if (tolog == true)
        //            {
        //                BesLog::DebugPrint("Buffer is empty!\n", BesLog::LOG_MESSAGE_TYPE_NORMAL, true);
        //            }
        //        }
    }
    pclose(fp);

    //    if (tolog == true)
    //    {
    //        BesLog::DebugPrint("ShellValue Size:" + Number2String(ValueList.size()) + string("\n"), BesLog::LOG_MESSAGE_TYPE_NORMAL, true);
    //        for (int i = 0; i < ValueList.size(); i++)
    //        {
    //            BesLog::DebugPrint("ShellValue:" + ValueList[i] + string("\n"), BesLog::LOG_MESSAGE_TYPE_NORMAL, true);
    //        }
    //    }

    return ValueList;
}

/*
 *  功能：
 *      获取执行路径名
 *  参数：
 *      无
 *  返回：
 *      执行路径名
 */
string BesEncryptF::GetExecutePath()
{
    char LinkPath[DEFAULT_BUFFER_SIZE + 1];
    bzero(LinkPath, sizeof (LinkPath));
    string ExecPath = "";
    string FileName = string("/proc/") + Number2String(getpid()) + string("/exe");
    int Res = readlink(FileName.c_str(), LinkPath, sizeof (LinkPath));
    if (Res != -1)
    {
        LinkPath[Res] = DEFAULT_C_STRING_END_FLAG;
        ExecPath = LinkPath;
        ExecPath = ExecPath.substr(0, ExecPath.find_last_of(LINUX_PATH_SEPCHAR) + 1);
    }
    return ExecPath;
}

/*
 *  功能：
 *      文件是否存在
 *  参数：
 *      file            :   文件名
 *  返回：
 *      如果存在返回true，否则返回false
 */
bool BesEncryptF::IsFileExist(string file)
{
    return (access(file.c_str(), F_OK) == 0);
}

/*
 *  功能：
 *      复制文件
 *  参数：
 *      source          :   源文件名
 *      dest            :   目标文件名
 *      overwrite       :   是否覆盖
 *  返回：
 *      操作成功返回true,否则返回false
 */
bool BesEncryptF::CopyFile(string source, string dest, bool overwrite, bool debug)
{
    //    // 检查源文件是否存在
    //    if (BeGeneralLib::IsFileExist(source) == false && (source.find_last_of(SEPARATOR_CHAR_ASTERISK) != source.size() - 1))
    //    {
    //        return false;
    //    }
    //
    //    // 如果不覆盖，并且目标文件存在，则返回
    //    if (overwrite == false && BeGeneralLib::IsFileExist(dest) == true)
    //    {
    //        return true;
    //    }
    //
    //    // 如果覆盖，并且目标文件存在，则删除
    //    if (overwrite == true && BeGeneralLib::IsFileExist(dest) == true)
    //    {
    //        //  BeGeneralLib::ForceRemoveDirectory(dest);
    //    }

    // 复制文件
    string ShellCommand = string("\\cp -f") + SEPARATOR_CHAR_SPACE + source + SEPARATOR_CHAR_SPACE + dest;
    ExecuteSystem(ShellCommand);

    // 检查目标文件是否存在
    return IsFileExist(dest);
}

/*
 *  功能：
 *      十六进制转换为十进制
 *  参数：
 *      str             :   十六进制字符串
 *  返回：
 *      转换后的十进制数
 */
int BesEncryptF::HexToDecimal(string str)
{
    str = StringToUpper(str);
    int Size = str.size();
    int DecValue = 0;
    for (int i = 0; i < Size; i++)
    {
        unsigned char Val = 0;
        char Ch = str.substr(i, 1).c_str()[0];
        switch (Ch)
        {
            case 'F':
            case 'E':
            case 'D':
            case 'C':
            case 'B':
            case 'A':
            {
                Val = Ch - 'A' + 10;
                break;
            }
            default:
            {
                Val = StringToInt(str.substr(i, 1));
                break;
            }
        }
        DecValue = DecValue + (int) Val * (int) pow(16, Size - i - 1);
    }
    return DecValue;
}

/*
 *  功能：
 *      将数组转换为十六进制字符串
 *  参数：
 *      arr             :   数组
 *      len             :   数组长度
 *  返回：
 *      转换后的十六进制字符串
 */
string BesEncryptF::ArrayToHexString(unsigned char *arr, int len)
{
    if (arr == NULL || len <= 0)
    {
        return "";
    }
    //    cout << "len:" << len << endl;
    string HexString = "";
    for (int i = 0; i < len; i++)
    {
        HexString = HexString + ByteToHexString((unsigned char) arr[i], true);
    }
    return HexString;
}

/*
 *  功能：
 *      将字节转换为十六进制字符串
 *  参数：
 *      byte            :   字节
 *      isupper         :   是否大写
 *  返回：
 *      转换后的十六进制字符串
 */
string BesEncryptF::ByteToHexString(unsigned char ch, bool isupper)
{
    unsigned char buf[3];
    bzero(buf, sizeof (buf));
    string format = (isupper == true) ? string("%02X\0") : string("%02x\0");
    sprintf((char*) buf, format.c_str(), ch);
    return string((const char *) buf);
}

/*
 *  功能：
 *      获取当前时间格式
 *  参数：
 *      format           :   时间格式
 *  返回：
 *      时间字符串
 */
string BesEncryptF::GetTimeString(BesEncryptF::TimeFormat format)
{
    // 获取当前时间
    time_t NowTime;
    time(&NowTime);

    return GetTimeString(NowTime, format);
}

/*
 *  功能：
 *      获取当前时间格式
 *  参数：
 *      time            :   时间
 *      format          :   时间格式
 *  返回：
 *      时间字符串
 */
string BesEncryptF::GetTimeString(time_t time, BesEncryptF::TimeFormat format)
{
    return GetTimeString(localtime(&time), format);
}

/*
 *  功能：
 *      获取当前时间格式
 *  参数：
 *      tmptr           :   时间结构指针
 *      format          :   时间格式
 *  返回：
 *      时间字符串
 */
string BesEncryptF::GetTimeString(struct tm *tmptr, BesEncryptF::TimeFormat format)
{
    char Buf[DEFAULT_BUFFER_SIZE + 1];
    bzero(Buf, sizeof (Buf));

    // 获取本地时间
    struct tm * CurrentTime = tmptr;

    string FormatString = GetTimeFormatString(format);

    // 转换为YYYYMMDDHHMMSS格式
    strftime(Buf, sizeof (Buf) - 1, FormatString.c_str(), CurrentTime);
    string TimeString = string(Buf);
    if (format == BesEncryptF::TIME_FORMAT_COMMAND_HEADER)
    {
        struct timeval NowTime;
        gettimeofday(&NowTime, NULL);
        bzero(Buf, sizeof (Buf));
        sprintf(Buf, "%06ld", NowTime.tv_usec);
        TimeString = TimeString + string(Buf);
    }
    return TimeString;
}

/*
 *  功能：
 *      获取日期格式字符串
 *  参数
 *      format          :   日期格式
 *  返回：
 *      日期格式字符串
 */
string BesEncryptF::GetTimeFormatString(BesEncryptF::TimeFormat format)
{
    string FormatString = "";
    switch (format)
    {
        case BesEncryptF::TIME_FORMAT_LONG:
        {
            FormatString = string("%Y-%m-%d %H:%M:%S");
            break;
        }
        case BesEncryptF::TIME_FORMAT_DATE:
        {
            FormatString = string("%Y-%m-%d");
            break;
        }
        case BesEncryptF::TIME_FORMAT_TIME:
        {
            FormatString = string("%H:%M:%S");
            break;
        }
        case BesEncryptF::TIME_FORMAT_FULL_DATETIME:
        {
            FormatString = string("%Y%m%d%H%M%S");
            break;
        }
        case BesEncryptF::TIME_FORMAT_FULL_DATE:
        {
            FormatString = string("%Y%m%d");
            break;
        }
        case BesEncryptF::TIME_FORMAT_FULL_TIME:
        {
            FormatString = string("%H%M%S");
            break;
        }
        case BesEncryptF::TIME_FORMAT_YEAR:
        {
            FormatString = string("%Y");
            break;
        }
        case BesEncryptF::TIME_FORMAT_MONTH:
        {
            FormatString = string("%m");
            break;
        }
        case BesEncryptF::TIME_FORMAT_DAY:
        {
            FormatString = string("%d");
            break;
        }
        case BesEncryptF::TIME_FORMAT_HOUR:
        {
            FormatString = string("%H");
            break;
        }
        case BesEncryptF::TIME_FORMAT_MINUTE:
        {
            FormatString = string("%M");
            break;
        }
        case BesEncryptF::TIME_FORMAT_SECOND:
        {
            FormatString = string("%S");
            break;
        }
        case BesEncryptF::TIME_FORMAT_COMMAND_HEADER:
        {
            FormatString = string("%d%H%M%S");
            break;
        }
    }
    return FormatString;
}

/*
 *  功能：
 *      打印调试信息
 *  参数：
 *      msg             :   文件名
 *  返回：
 *      无
 */
void BesEncryptF::DebugPrint(string msg)
{
    cout << msg << endl;
}
