#ifndef __HASH_ENGINE_H_
#define __HASH_ENGINE_H_

#include <sys/types.h>
// #include <db.h>

typedef struct {
	void		*data;
	u_int32_t	size;
} DBDT;

typedef	void (*HASHENG_callback)(const u_char *, int);

typedef struct _hashing_engine {
	struct _hashing_engine*  (*init)(char *sign, ...);

	void	*variables;
	int	(*put)(struct _hashing_engine *this, DBDT *key, DBDT *val,
				const int pos);
	int	(*get)(struct _hashing_engine *this,
				DBDT *key, DBDT *val, int *pos,
				int (*callback)(const int));
	int	(*del)(struct _hashing_engine *this, DBDT *key,
				int (*callback)(const int));
	int	(*firstkey)(struct _hashing_engine *this, DBDT *key, DBDT *val);
	int	(*nextkey)(struct _hashing_engine *this , DBDT *key, DBDT *val);
	int	(*release)(struct _hashing_engine *this);
	char*	(*error)(struct _hashing_engine *this);
	int	*max_bits;
} HASHENG;

int		HASHENG_regist_implementation (const char *sign, HASHENG *imp);
HASHENG*	HASHENG_request_implementation (const char *sign);
void		HASHENG_init_hashing_engine (void);


#define HASHENG_regist_functions(x)	{		\
			x.variables = &variables;	\
		        x.init      = init;		\
		        x.put       = put;		\
			x.get       = get;		\
			x.del       = del;		\
			x.firstkey  = firstkey;		\
			x.nextkey   = nextkey;		\
			x.release   = release;		\
			x.max_bits  = &max_bits;	\
			x.error     = error; }

#endif

int init_hashing_engine_berkeley_db (void);
int init_hashing_engine_memory_hash (void);
