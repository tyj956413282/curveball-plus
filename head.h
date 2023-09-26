#ifndef _HEAD_H
#define _HEAD_H

#define MINIMUM_CACHE			// 使用“小量证书缓存”；否则使用“全量证书缓存”
#define MINIMUM_FINAL_KEY		// 当使用“小量证书缓存”时生效：存储最终公钥值；否则存储公钥重构值
#define EXTENDED_MINIMUM			// 当使用“小量证书缓存”时生效：增加辅助计算值；否则无此值只能验根
#define NO_CURVEBALL_BUG			// 没有Curveball漏洞；否则忽略曲线参数比对

// #define VALIDATE_PRINT_STEP
// #define VALIDATE_DEBUG
// #define MINIMUM_CACHE_DEBUG
// #define MAKE_CERT_DEBUG
// #define TEST_PRINTKEY


// mode print string

#ifdef MINIMUM_CACHE
#define CACHE_STR "minimum_cache"
#else
#define CACHE_STR "normal_cache"
#endif


#endif