#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*hello_function)(void);

int main (int argc, char *argv[]) {
	void		*library;
	hello_function	hello;
	const char	*error;


	library = dlopen ("./libhello.so", RTLD_LAZY);

	if (library == NULL) {
		// 	perror ("libhello.so");
		fprintf (stderr, "%s\n", dlerror ());
		exit (1);
	}

	dlerror ();

	hello = dlsym (library, "print_hello");

	error = dlerror ();

	if (error) {
		fprintf (stderr, "Could not find print_hello: %s\n", error);
		exit (1);
	}

	(*hello)();

	dlclose (library);

	return 0;
}
