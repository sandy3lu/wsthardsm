#ifndef CONTEXT_H
#define CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_NUMBER   8


typedef struct {
    int device_type;
    char api_version[33];
    int device_count;
    DeviceContext device_list[MAX_DEVICE_NUMBER];
} CryptoContext;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      上下文管理
// 这部分接口为上下文管理接口，包括初始加载资源，最后释放资源，查询状态等
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* 初始化函数库，会创建初始的上下文信息，应该在调用其他任何函数之前先调用本函数 */
int init();

/* 清理函数库，释放该函数库所占用的一切资源，应该在不需要使用函数库时调用本函数，
 * 已确保加密卡硬件资源得到正确释放，否者加密卡可能陷入不一致的状态 */
int finit();

/* 统计检测到的加密卡数量 */
int ctx_device_count();

/* 打开指定索引的加密卡设备，比如主机插有 2 块加密卡，那么其索引分别为 0, 1.
 * 该打开方式有两个特性:
 * 1. 幂等性，一个进程可以多次调用该函数打开同一个加密卡，效果与只调用一次等同，也只需关闭一次即可
 * 2. 非独占，一个进程打开某个加密卡的情况下，其他进程也能独立打开，并且谁打开谁负责关闭 */
int ctx_open_device(int index);

/* 关闭指定索引的加密卡设备，无论加密卡是否已关闭 */
int ctx_close_device(int index);

/* 一次性关闭该进程使用的所有加密卡 */
int ctx_close_all_devices();

/* 实时获取指定加密卡的状态信息 */
int ctx_get_device_status(int index, DeviceStatus *device_status);

/* 实时获取所有加密卡的状态信息 */
DeviceStatuses ctx_get_device_statuses();

/* 加密卡设备自检 */
int ctx_check_device(int index);

/* 打印所有的上下文信息，verbose = true 时打印详细信息，否者打印简略信息
 * 打印内容会比较多，因此确保 buf 有足够大的空间，否者可能段错误，一般不应小于 1024 * 32 字节 */
void ctx_print_context(char *buf, int buf_len, bool verbose);

/* 打开某个加密卡上的所有安全通道，比如 westone B 卡有 32 个通道，
 * 一次性打开所有通道，是为了上层以多线程方式调用加密卡，充分利用加密卡资源，提升性能。
 * 该函数也是幂等的，可重复调用，无副作用。*/
int ctx_open_pipes(int index);

/* 关闭某个加密卡上的所有安全通道，满足幂等性 */
int ctx_close_pipes(int index);

/* 关闭某个加密卡上的所有安全通道，满足幂等性，实现方式与 ctx_close_pipe 不同。
 * ctx_close_pipe 是手动一个一个关闭通道的，而本函数是调用加密卡方法一次性关闭的。
 * 推荐使用本函数而非 ctx_close_pipe。*/
int ctx_close_all_pipe(int index);

/* 登录某个加密卡, 8 <= len(pin_code) <= 256，满足幂等性 */
int ctx_login(int index, const char *pin_code);

/* 登出某个加密卡，满足幂等性 */
int ctx_logout(int index);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      算法
// 这部分为算法接口，用户自行各类加密算法，以及各类密钥管理
// 为了支持多线程高性能的加密算法，所有 API 都支持自由选择设备和通道进行计算，应用层可以开辟线程池并每个线程占用一个通道。
// 加密卡设备的上下文状态可能是动态变化的，比如设备增加或者减少，比如通道打开或者关闭，而另一方面应用可能正在高速进行加密运算，
// 为了让上下文状态的变化尽可能减少对应用的影响，也为了保证算法接口的容错性，所有传入的 device_index 和 pipe_index 都会被进行哈希处理,
// 也就是说调用者不论传入什么 device_index 和 pipe_index 进来，都能找到对应的加密卡资源进行处理。
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* 三段式哈希，针对大块数据
 * 1. init 初始化
 * 2. 0 或 n 次 update，填装待哈希的数据
 * 3. 最后一次填装数据并计算哈希值，哈希值以 16 进制编码存储于 out 中，所以 out_len 必须不小于 32 * 2 + 1 = 65
 * 这三段中，ctx_digest_init 和 ctx_digest_final 必不可少，也不满足幂等性 */
int ctx_digest_init(int device_index, int pipe_index);
int ctx_digest_update(int device_index, int pipe_index, const char *data, int data_len);
int ctx_digest_final(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len);

/* 一次性哈希，针对少量数据，哈希值以 16 进制编码存储于 out 中，所以 out_len 必须不小于 32 * 2 + 1 = 65 */
int ctx_digest(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len);

/* 获取硬件随机数，16 进制编码存储于 out
 * (out_len - 1) / 2 指明要获取的随机数长度，比如想要获取 32 字节长度随机数，那么 out_len = 65
 * 3 < len(out_len) < 2045 */
int ctx_random(int device_index, int pipe_index, char *out, int out_len);

/* 生成 SM4 对称密钥，128 bits，以 16 进制编码存储于 out 中，out_len 必须不小于 16 * 2 + 1 = 33
 * protect = true 时密钥以密文形式导出
 * protect = false 时密钥以明文形式导出 */
int ctx_generate_key(int device_index, int pipe_index, bool protect, char *out, int out_len);

int ctx_generate_keypair(int device_index, int pipe_index,
                         char *public_key, int public_key_len, char *private_key, int private_key_len);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* 以下为模块内部调用函数 */
int print_device_context(DeviceContext *device_context, char *buf);
int print_statistics(CryptoContext *crypto_context, char *buf);
int print_device_status(DeviceStatus *device_status, char *buf);
int print_device_statuses(DeviceStatuses *device_statuses, char *buf);


#ifdef __cplusplus
}
#endif

#endif
