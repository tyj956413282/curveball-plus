#ifndef _HEAD_H
#define _HEAD_H

#define MINIMUM_CACHE			// ʹ�á�С��֤�黺�桱������ʹ�á�ȫ��֤�黺�桱
#define MINIMUM_FINAL_KEY		// ��ʹ�á�С��֤�黺�桱ʱ��Ч���洢���չ�Կֵ������洢��Կ�ع�ֵ
#define EXTENDED_MINIMUM			// ��ʹ�á�С��֤�黺�桱ʱ��Ч�����Ӹ�������ֵ�������޴�ֵֻ�����
#define NO_CURVEBALL_BUG			// û��Curveball©��������������߲����ȶ�

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