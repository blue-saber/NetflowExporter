#ifndef _LIUJC_UTILS_H_
#define _LIUJC_UTILS_H_

#include <sys/types.h>

extern u_char * text2macaddr (const char *str, u_char *macaddr);
extern u_char * print_ether  (const u_char *mac);
extern u_char * print_mac    (const u_char *mac);
extern u_char * print_ip     (const u_char *ipstr);
extern u_char * timet_2_mysql_datetime (const time_t *ptr);
extern int	 check_byte_ending (void);
extern void   * utils_calloc (size_t nmemb, size_t size);
extern void   * utils_malloc (size_t size);
extern int      utils_memuse (void);
extern int      is_numeric_string (const char *str);


#endif
