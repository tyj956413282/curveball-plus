#include "head.h"
#include "test.h"
#include "ecqv.h"

void print_code_type() {
	printf("Validate Type: Certificate Cache - ");
#ifdef MINIMUM_CACHE
	#ifdef EXTENDED_MINIMUM
	printf("extended-minimum-");
	#else 
		printf("minimum-");
	#endif // EXTENDED_MINIMUM
	#ifdef MINIMUM_FINAL_KEY
		printf("Vp");
	#else
		printf("Vq");
	#endif // MINIMUM_FINAL_KEY
#else
	printf("normal-Vq");
#endif // MINIMUM_CACHE
	printf(", ");
#ifdef NO_CURVEBALL_BUG
	printf("with no Curveball bug");
#else
	printf("with Curveball bug");
#endif
	printf("\n");
	// getchar();
	return ;
}

int main() {
	print_code_type();
	ecqv_init();

	// test_ecqv();
	// test32();
	test33(5);
	//test35(5);
	// test41_curveball_explicit();

	// test6_generate_certs();
	// test6_read_file();

	// test71();

	ecqv_uninit();
	print_code_type();
	return 0;
}