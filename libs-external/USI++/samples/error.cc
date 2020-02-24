#include <usi++/usi++.h>

/* Example for libusi++ error-handling.
 * We try to set a filter on an NOT initialized device.
 * MUST BE LINKED STATIC with usi++. (somehow C++ exceptions dont work with .so)
 */

int main()
{
   	TCP *x = new TCP("127.0.0.1");

	/* turn on using exceptions */
	useException(true);

	try {
		x->setfilter("false");
	} catch (usifault &u) {
		printf("Caught exception: %s\n", u.why()); 
	}
	printf("Try to setfilter again.\n");

	/* use normal error-handling (default) and let usi++
	 * generate nice error-messages and exiting
	 */
	useException(false);
	x->setfilter("false");

	/* NOT reached */
}

